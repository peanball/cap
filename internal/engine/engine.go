// Package engine wires pcap decoding, TCP reassembly (gopacket reassembly),
// matchers, and pcap output into a single-threaded pipeline.
//
// Per stream: packet records are buffered in streamState.pending. Once any
// matcher signals Match, pending is replayed in arrival order and future
// packets for that stream forward directly. On NoMatch, pending is dropped.
// Stream state accumulates only for unmatched streams; matched ones still
// get state entries for cleanup but skip reassembly (Accept returns false).
// A matched stream that closes lingers briefly so its late packets (final
// ACK, RSTs) are still forwarded, then is evicted.
package engine

import (
	"cmp"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"go.peanball.net/cap/internal/match"
	"go.peanball.net/cap/internal/pcap"
	"go.peanball.net/cap/internal/proxyhdr"
	"go.peanball.net/cap/internal/tlsch"
)

// Config controls engine behavior. Zero values are replaced by defaults.
type Config struct {
	Matcher match.Matcher // byte-stream matcher; optional

	// KeyMatchers gate streams by their identity (IPs, ports, tunneled-ness).
	// If any are configured, a stream passes only if ALL match. ANDed with
	// the byte matchers when both are present.
	KeyMatchers []match.KeyMatcher

	// IdleTimeout evicts unmatched streams without assembly progress.
	// Matched streams are exempt. Default 60 s. Enforcement happens via
	// FlushCloseOlderThan on each Process call.
	IdleTimeout time.Duration

	// MaxStreams bounds concurrent streams. Past the cap, the factory
	// returns a discard-all stream — the conn goes untracked. Default 100_000.
	MaxStreams int

	// WindowBytes is the per-direction reassembly window consulted by
	// matchers; streams exceeding it taint and become unmatched.
	// Default 64 KiB.
	WindowBytes int

	// PendingBytesPerStream caps the total bytes retained in pending for
	// replay. If exceeded pre-match, the stream is dropped as a side effect
	// of taint-on-overflow. Default 4 MiB.
	PendingBytesPerStream int

	// Unpack duplicates or rewrites packets of kept streams so hidden parts
	// of the envelope become visible: in-6 tunnels (IPv4 or IPv6 payload)
	// emit a copy of the inner packet reframed on the outer link layer,
	// and PROXY-fronted connections emit copies whose 5-tuple is the one
	// the header asserts.
	Unpack bool

	// Linger is how long a kept stream, once closed (FIN from both sides, or
	// RST), keeps forwarding its late packets: the final ACK, RSTs and
	// retransmitted FINs. It is measured in packet time, and a lingering
	// stream still counts toward MaxStreams. Default 5 s.
	Linger time.Duration
}

// Stats counters.
type Stats struct {
	PacketsIn    uint64
	PacketsOut   uint64
	StreamsTotal uint64
	StreamsKept  uint64
	StreamsDrop  uint64
	StreamsTaint uint64

	// ECHDropped counts dropped streams whose ClientHello carried an
	// encrypted_client_hello extension. It includes GREASE ECH, which
	// browsers send on ordinary connections, and says nothing about why the
	// stream was dropped; see ECHNames to tell the two apart.
	ECHDropped uint64
}

// Engine drives the pipeline. Single caller goroutine only.
type Engine struct {
	cfg Config
	out *pcap.Writer

	pool *reassembly.StreamPool
	asm  *reassembly.Assembler
	fac  *factory

	// streams maps flowKey to streamState (one per connection).
	streams map[flowKey]*streamState

	// proxy maps flowKey to the stream's PROXY header state, for unpacking.
	// Only non-nil when cfg.Unpack is set; entries are deleted by evict.
	proxy map[flowKey]*proxyTrack

	// link is the most recent input link type, used by unpack to reframe
	// copies. Set on each Process call (inputs are one stream: one type).
	link pcap.LinkType

	stats Stats

	// echNames counts ECHDropped by the ClientHello's outer SNI, capped at
	// maxECHNames distinct names.
	echNames map[string]uint64

	// lastFlush is when we last ran FlushCloseOlderThan; throttle to 1 Hz.
	lastFlush time.Time

	// lingerQ holds closed kept streams in the order they closed, which is
	// the order their linger windows end.
	lingerQ []*streamState

	// flushAdvised is set when a packet written completes a kept
	// connection's output; see FlushAdvised.
	flushAdvised bool
}

// Stats returns a snapshot.
func (e *Engine) Stats() Stats { return e.stats }

// New builds an engine writing matched streams to out.
func New(cfg Config, out *pcap.Writer) (*Engine, error) {
	if cfg.Matcher == nil && len(cfg.KeyMatchers) == 0 {
		return nil, errors.New("engine: Matcher or KeyMatchers required")
	}
	if cfg.Matcher == nil {
		// No byte matchers: any stream that passes key matchers is kept.
		cfg.Matcher = alwaysMatch{}
	}
	if cfg.WindowBytes <= 0 {
		cfg.WindowBytes = 64 << 10
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.MaxStreams <= 0 {
		cfg.MaxStreams = 100_000
	}
	if cfg.PendingBytesPerStream <= 0 {
		cfg.PendingBytesPerStream = 4 << 20
	}
	if cfg.Linger <= 0 {
		cfg.Linger = 5 * time.Second
	}
	e := &Engine{cfg: cfg, out: out, streams: map[flowKey]*streamState{}}
	fac := &factory{eng: e}
	e.fac = fac
	e.pool = reassembly.NewStreamPool(fac)
	e.asm = reassembly.NewAssembler(e.pool)
	perConn := (cfg.WindowBytes / 1900) * 2
	if perConn < 8 {
		perConn = 8
	}
	e.asm.MaxBufferedPagesPerConnection = perConn
	e.asm.MaxBufferedPagesTotal = perConn * max(1, cfg.MaxStreams/10)
	return e, nil
}

// Process decodes data as the given link type and routes it. Returns nil for
// skipped (non-TCP/undecodable) packets; error only for unrecoverable output
// failures.
func (e *Engine) Process(link pcap.LinkType, ts time.Time, data []byte) error {
	e.stats.PacketsIn++
	e.sweepLingering(ts)
	e.link = link

	var pkt gopacket.Packet
	switch link {
	case pcap.LinkEthernet:
		pkt = gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
	case pcap.LinkLinuxSLL:
		pkt = gopacket.NewPacket(data, layers.LayerTypeLinuxSLL, gopacket.NoCopy)
	case pcap.LinkLinuxSLL2:
		pkt = gopacket.NewPacket(data, layers.LayerTypeLinuxSLL2, gopacket.NoCopy)
	case pcap.LinkIPv4:
		pkt = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
	case pcap.LinkIPv6:
		pkt = gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
	case pcap.LinkRaw:
		if len(data) == 0 {
			return nil
		}
		if data[0]>>4 == 6 {
			pkt = gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.NoCopy)
		} else {
			pkt = gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.NoCopy)
		}
	default:
		return fmt.Errorf("unsupported linktype %d", link)
	}

	tcpLayer := pkt.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return nil
	}
	nfl := pkt.NetworkLayer()
	if nfl == nil {
		return nil
	}

	// Tunnel detection: IPv6 with NextHeader 4 (IPv4 payload) or 41 (a
	// nested IPv6 packet) means the payload is a tunneled packet.
	// We peel one layer, decode the inner, but retain outer tuple for
	// tunneled-stream key matching. Output records remain verbatim.
	var (
		srcIP, dstIP       netip.Addr
		isTunneled         bool
		outerSrc, outerDst netip.Addr
	)
	if ip6, ok := nfl.(*layers.IPv6); ok &&
		(ip6.NextHeader == layers.IPProtocolIPv4 || ip6.NextHeader == layers.IPProtocolIPv6) {
		// nfl is the outer IPv6. gopacket decodes the tunneled packet as
		// the next layer; it is the first IPv4/second IPv6 layer overall.
		var inner gopacket.NetworkLayer
		n6 := 0
		for _, lt := range pkt.Layers() {
			switch il := lt.(type) {
			case *layers.IPv4:
				inner = il
			case *layers.IPv6:
				n6++
				if n6 == 2 {
					inner = il
				}
			}
		}
		if inner == nil {
			return nil
		}
		isTunneled = true
		outerSrc, _ = netip.AddrFromSlice(ip6.SrcIP)
		outerDst, _ = netip.AddrFromSlice(ip6.DstIP)
		srcIP, dstIP = flowIPs(inner)
	} else {
		srcIP, dstIP = flowIPs(nfl)
	}

	key := makeKey(srcIP, dstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort))
	st, tracked := e.streams[key]
	if tracked && st.lingering && tcp.SYN && !tcp.ACK {
		// The 4-tuple is being reused: this starts a new connection rather
		// than being a straggler of the closed one.
		e.evict(st)
		st, tracked = nil, false
	}

	if !tracked {
		// First packet of a candidate stream. Run key matchers.
		if len(e.cfg.KeyMatchers) > 0 {
			sp, dp := uint16(tcp.SrcPort), uint16(tcp.DstPort)
			info := &match.StreamInfo{
				IsTunneled: isTunneled,
				// SrcIP/DstIP are the OUTER tunnel endpoints for tunneled,
				// the plain stream's endpoints otherwise.
				OuterSrcIP: ternaryAddr(isTunneled, outerSrc, srcIP),
				OuterDstIP: ternaryAddr(isTunneled, outerDst, dstIP),
				// Outer ports exist only for non-tunneled (4-in-6 carries none).
				OuterSrcPort: ternaryU16(isTunneled, 0, sp),
				OuterDstPort: ternaryU16(isTunneled, 0, dp),
				// Inner ports = the TCP ports as decoded (which, for tunneled,
				// are the inner TCP's; for plain streams, equal to outer).
				InnerSrcPort: sp,
				InnerDstPort: dp,
			}
			for _, km := range e.cfg.KeyMatchers {
				if !km.ConsiderKey(info) {
					return nil
				}
			}
		}
	}
	// Fast path: matched stream — forward without touching assembler.
	if tracked && st.verdict == match.Match {
		if st.lingering {
			// Straggler of a connection that already closed. Forward it; it
			// is the last of the connection's output, so advise a flush.
			e.flushAdvised = true
			return e.emitPacket(key, ts, data)
		}
		// Track close on the engine side. After Match, Accept returns false
		// so the assembler stops tracking this conn — its ReassemblyComplete
		// will never fire, meaning engine.streams would leak without this.
		closing := false
		if tcp.RST {
			closing = true
		} else if tcp.FIN {
			// Bit 0 = canonical "A" side closed, bit 1 = "B" side.
			// A sides are normalized so srcIP==addrA↔SrcPort==portA iff this
			// packet is from side A.
			srcIsA := srcIP.Compare(key.addrA) == 0 && uint16(tcp.SrcPort) == key.portA
			var bit uint8
			if srcIsA {
				bit = 1 << 0
			} else {
				bit = 1 << 1
			}
			prev := st.closedHalves
			st.closedHalves |= bit
			closing = prev != st.closedHalves && st.closedHalves == 0b11
		}
		err := e.emitPacket(key, ts, data)
		if closing {
			e.startLinger(st, ts)
		}
		return err
	}
	// Fast path: already decided NoMatch or tainted — drop.
	if tracked && (st.verdict == match.NoMatch || st.tainted) {
		return nil
	}
	// Undecided: capture into pending, then assemble.
	if tracked {
		if st.pendingBytes()+len(data) > e.cfg.PendingBytesPerStream {
			st.tainted = true
			e.stats.StreamsTaint++
			delete(e.streams, key)
			return nil
		}
		cp := make([]byte, len(data))
		copy(cp, data)
		st.pending = append(st.pending, pendingRecord{ts: ts, data: cp})
	}

	// Feed the assembler. If this is a *new* connection, the assembler
	// calls factory.New synchronously; we pick up the new streamState and
	// register it under our key so the next packet routes directly.
	e.asm.AssembleWithContext(nfl.NetworkFlow(), tcp, &simpleCtx{
		ci: gopacket.CaptureInfo{Timestamp: ts, Length: len(data), CaptureLength: len(data)},
	})
	if fresh := e.fac.adopt(); fresh != nil {
		// Bytes of this packet belong in pending for replay.
		cp := make([]byte, len(data))
		copy(cp, data)
		fresh.pending = append(fresh.pending, pendingRecord{ts: ts, data: cp})
		e.registerStream(fresh, key)
		if e.cfg.Unpack {
			e.noteUnpack(key, srcIP, dstIP, tcp)
		}
	}

	// Periodic idle eviction, throttled to 1 Hz.
	if ts.Sub(e.lastFlush) >= time.Second {
		e.lastFlush = ts
		e.asm.FlushCloseOlderThan(ts.Add(-e.cfg.IdleTimeout))
	}
	return nil
}

// startLinger marks a kept stream closed. It stays in e.streams until its
// linger window ends, so late packets of the connection are still forwarded.
func (e *Engine) startLinger(st *streamState, ts time.Time) {
	st.lingering = true
	st.lingerUntil = ts.Add(e.cfg.Linger)
	e.lingerQ = append(e.lingerQ, st)
	e.flushAdvised = true
}

// sweepLingering evicts closed kept streams whose linger window has ended as
// of ts. Streams close in time order, so only the head needs checking.
func (e *Engine) sweepLingering(ts time.Time) {
	for len(e.lingerQ) > 0 && !ts.Before(e.lingerQ[0].lingerUntil) {
		e.evict(e.lingerQ[0])
		e.lingerQ[0] = nil
		e.lingerQ = e.lingerQ[1:]
	}
}

// evict removes st from the stream table, unless a newer connection has
// already taken its key.
func (e *Engine) evict(st *streamState) {
	if e.streams[st.key] == st {
		delete(e.streams, st.key)
		delete(e.proxy, st.key)
	}
}

// FlushAdvised reports, and clears, whether packets written since the last
// call completed a kept connection's output: the packet that closed it, or a
// straggler after it. The caller decides whether to flush; a buffered writer
// that flushes on this sees whole connections promptly without paying a
// write per packet.
func (e *Engine) FlushAdvised() bool {
	advised := e.flushAdvised
	e.flushAdvised = false
	return advised
}

// flowIPs extracts src/dst IP from the decoded network layer.
func flowIPs(nfl gopacket.NetworkLayer) (netip.Addr, netip.Addr) {
	switch nl := nfl.(type) {
	case *layers.IPv4:
		s, _ := netip.AddrFromSlice(nl.SrcIP)
		d, _ := netip.AddrFromSlice(nl.DstIP)
		return s, d
	case *layers.IPv6:
		s, _ := netip.AddrFromSlice(nl.SrcIP)
		d, _ := netip.AddrFromSlice(nl.DstIP)
		return s, d
	}
	return netip.Addr{}, netip.Addr{}
}

// registerStream is called by factory.New to add a newly-seen stream into
// e.streams. The assembler has already decided to track it.
func (e *Engine) registerStream(st *streamState, key flowKey) {
	if len(e.streams) >= e.cfg.MaxStreams {
		// Over cap: refuse tracking. Returning st anyway (assembler needs a
		// Stream) but mark tainted so Accept drops all packets.
		st.tainted = true
		e.stats.StreamsTaint++
		return
	}
	e.streams[key] = st
	st.key = key
	e.stats.StreamsTotal++
}

// onMatch is called from streamState when a matcher first fires. Replays
// pending to the output, then releases reassembly/prefix buffers — they're
// dead weight once the stream is matched.
func (e *Engine) onMatch(st *streamState) {
	e.stats.StreamsKept++
	if e.cfg.Unpack {
		// Discover a PROXY header in the buffered client prefix. Errors are
		// definitive (c2s, not client, or too many bytes) — mark none.
		if pt := e.proxy[st.key]; pt != nil && len(st.buf) > 0 {
			if info, err := proxyhdr.Parse(st.buf); err == nil && info.SrcIP.IsValid() {
				pt.hdr, pt.hdrEnd, pt.has = info, int64(info.Length), true
			}
		}
	}
	for _, pr := range st.pending {
		if err := e.emitPacket(st.key, pr.ts, pr.data); err != nil {
			// Out failures are sticky in the writer; further attempts no-op.
			return
		}
	}
	st.pending = nil
	st.buf = nil // matcher prefix never consulted post-match
}

// onNoMatch drops the stream's retained records.
func (e *Engine) onNoMatch(st *streamState) {
	e.stats.StreamsDrop++
	e.noteDroppedECH(st.buf)
	st.pending = nil
}

// maxECHNames bounds the echNames table. The outer SNI is chosen by the
// peer, so an unbounded table would be a memory lever. Once full, new names
// still count toward Stats.ECHDropped but are not itemized.
const maxECHNames = 1024

// ECHName counts dropped ECH ClientHellos that shared one outer SNI.
type ECHName struct {
	SNI   string // "" if the ClientHello had no server_name
	Count uint64
}

// ECHNames returns the dropped ECH ClientHellos grouped by outer SNI, most
// frequent first. A real ECH offer carries the ECHConfig's public_name there
// (e.g. one name shared by a whole CDN), while GREASE ECH carries the name
// the client is really connecting to, so a name dominating the list points
// at real ECH.
func (e *Engine) ECHNames() []ECHName {
	out := make([]ECHName, 0, len(e.echNames))
	for sni, n := range e.echNames {
		out = append(out, ECHName{SNI: sni, Count: n})
	}
	slices.SortFunc(out, func(a, b ECHName) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), strings.Compare(a.SNI, b.SNI))
	})
	return out
}

// noteDroppedECH records a dropped stream whose buffered prefix is a
// ClientHello offering ECH. Streams dropped before the ClientHello was fully
// buffered, or that are not TLS, are not counted.
func (e *Engine) noteDroppedECH(buf []byte) {
	info, err := tlsch.Parse(buf)
	if err != nil || info.ECH == nil {
		return
	}
	e.stats.ECHDropped++
	if _, seen := e.echNames[info.SNI]; seen || len(e.echNames) < maxECHNames {
		if e.echNames == nil {
			e.echNames = map[string]uint64{}
		}
		e.echNames[info.SNI]++
	}
}

// onTaint marks stream unusable.
func (e *Engine) onTaint(st *streamState) {
	e.stats.StreamsTaint++
	st.pending = nil
}

// onComplete is invoked on stream ReassemblyComplete (FIN/RST received
// while assembler still tracked it, or FlushCloseOlderThan eviction).
// Removes our entry from the streams map.
func (e *Engine) onComplete(st *streamState) {
	// Fast path: if the stream has a computed key, delete directly, but not
	// an entry that a newer connection on the same 4-tuple has taken over.
	if st.key != (flowKey{}) {
		e.evict(st)
		return
	}
	// Slow path: defensive scan. Unused once registerStream sets st.key.
	for k, v := range e.streams {
		if v == st {
			delete(e.streams, k)
			return
		}
	}
}

// writeRecord emits one pcap record to the output writer. It never flushes:
// when output reaches the consumer is the caller's policy (see cmd/cap -U).
// Timestamps pass through as time.Time; pcapgo formats the wire field.
// CapLen defaults to len(data) on the writer side; the engine always writes
// full frames.
func (e *Engine) writeRecord(ts time.Time, data []byte) error {
	rec := pcap.Record{Timestamp: ts, Data: data}
	if err := e.out.Record(rec); err != nil {
		return err
	}
	e.stats.PacketsOut++
	return nil
}

// Close flushes idle streams and unblocks Close. Caller is responsible for
// the output writer itself.
func (e *Engine) Close() {
	e.asm.FlushCloseOlderThan(time.Now().Add(24 * 365 * 10 * time.Hour))
}

// ternaryAddr returns t if isT else f.
func ternaryAddr(isT bool, t, f netip.Addr) netip.Addr {
	if isT {
		return t
	}
	return f
}

// ternaryU16 returns t if isT else f.
func ternaryU16(isT bool, t, f uint16) uint16 {
	if isT {
		return t
	}
	return f
}

// alwaysMatch is the Matcher used when only KeyMatchers are configured.
type alwaysMatch struct{}

func (alwaysMatch) Consider([]byte) match.Verdict { return match.Match }

// simpleCtx is an AssemblerContext carrying CaptureInfo.
type simpleCtx struct {
	ci gopacket.CaptureInfo
}

func (s *simpleCtx) GetCaptureInfo() gopacket.CaptureInfo { return s.ci }

// pendingBytes returns the total bytes held in pending.
func (s *streamState) pendingBytes() int {
	n := 0
	for _, p := range s.pending {
		n += len(p.data)
	}
	return n
}
