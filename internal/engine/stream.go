package engine

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/reassembly"

	"go.peanball.net/cap/internal/match"
)

// flowKey is the canonical bidirectional identifier of a TCP connection.
// Endpoints are sorted so both directions hash identically.
type flowKey struct {
	addrA, addrB netip.Addr
	portA, portB uint16
}

// makeKey normalizes a 5-tuple into a flowKey.
func makeKey(srcIP, dstIP netip.Addr, srcPort, dstPort uint16) flowKey {
	a, b, sp, dp := srcIP, dstIP, srcPort, dstPort
	if b.Less(a) || (b == a && dp < sp) {
		a, b, sp, dp = b, a, dp, sp
	}
	return flowKey{addrA: a, addrB: b, portA: sp, portB: dp}
}

// streamState implements reassembly.Stream for one bidirectional TCP
// connection. Created once per connection by factory.New; a single instance
// serves both halves (dir argument distinguishes).
//
// Single-goroutine by contract: the engine's Process path is the only
// caller. The stream is registered into Engine.streams by Process via the
// factory → engine handoff, not from New itself, because New lacks the
// decoded 5-tuple (flow endpoints are strings; parsing is fragile).
type streamState struct {
	eng *Engine

	verdict match.Verdict
	tainted bool

	// closedHalves tracks FIN or RST per direction. Set by the engine's
	// fast path when verdict==Match (assembler has been told to stop
	// tracking via Accept returning false, so we must track closes there).
	// Bit 0 = init(client)side closed, bit 1 = responder closed; the
	// stream starts lingering when both bits are set or on RST.
	closedHalves uint8

	// lingering marks a closed kept stream that is still in Engine.streams
	// to forward late packets until lingerUntil (packet time).
	lingering   bool
	lingerUntil time.Time

	// clientKnown/clientDir: which assembler-internal direction is the client.
	// Set only by observing which direction carried the SYN-without-ACK in
	// Accept. Mid-stream capture (no SYN seen) cannot identify the client
	// reliably; we mark tainted and skip the stream.
	clientKnown bool
	clientDir   reassembly.TCPFlowDirection

	// buf is the client→server reassembled prefix, capped at cfg.WindowBytes.
	buf         []byte
	winExceeded bool

	// pending holds verbatim packet records for replay on Match.
	// Populated by Engine.Process between stream lookup and assembler call.
	pending []pendingRecord

	// key is set by registerStream; used by onComplete for O(1) removal.
	key flowKey
}

type pendingRecord struct {
	ts   time.Time
	data []byte // owned copy
}

// factory implements reassembly.StreamFactory. New is invoked synchronously
// by Assembler.AssembleWithContext only when a genuinely new connection is
// observed; the caller on the engine side then adopts the stream.
type factory struct {
	eng      *Engine
	lastMade *streamState // consumed by Engine.Process via adopt()
}

func (f *factory) New(netFlow, tcpFlow gopacket.Flow, tcp *layers.TCP, ac reassembly.AssemblerContext) reassembly.Stream {
	st := &streamState{eng: f.eng, buf: make([]byte, 0, f.eng.cfg.WindowBytes)}
	f.lastMade = st
	return st
}

// adopt takes the streamState just produced by New (if any) and clears it.
func (f *factory) adopt() *streamState {
	s := f.lastMade
	f.lastMade = nil
	return s
}

func (s *streamState) Accept(tcp *layers.TCP, ci gopacket.CaptureInfo, dir reassembly.TCPFlowDirection, nextSeq reassembly.Sequence, start *bool, ac reassembly.AssemblerContext) bool {
	if s.tainted || s.verdict == match.NoMatch {
		return false
	}
	// The SYN sender is definitively the client. Record which assembler
	// direction it came from; gopacket assigns dir per conn, not globally.
	if !s.clientKnown && tcp.SYN && !tcp.ACK {
		s.clientDir = dir
		s.clientKnown = true
	}
	// Do NOT set *start=true on mid-stream data: a half-tracked connection
	// can't be reliably attributed to a client direction.
	if s.verdict == match.Match {
		return false // engine forwards directly, no need for assembly
	}
	return true
}

func (s *streamState) ReassembledSG(sg reassembly.ScatterGather, ac reassembly.AssemblerContext) {
	dir, _, _, _ := sg.Info()
	avail, _ := sg.Lengths()
	if avail == 0 {
		return
	}
	if !s.clientKnown {
		// Mid-stream capture without SYN: we cannot reliably identify the
		// client, and gopacket's dir assignments depend on internal
		// halfconnection ordering rather than handshake role. Safer to
		// skip than to mislabel the server's flight as the client's.
		return
	}
	if dir != s.clientDir || s.tainted || s.verdict != match.NeedMore {
		return
	}
	data := sg.Fetch(avail)
	if len(s.buf)+len(data) > s.eng.cfg.WindowBytes {
		s.tainted = true
		s.winExceeded = true
		s.eng.onTaint(s)
		return
	}
	s.buf = append(s.buf, data...)
	switch s.eng.cfg.Matcher.Consider(s.buf) {
	case match.Match:
		s.verdict = match.Match
		s.eng.onMatch(s)
	case match.NoMatch:
		s.verdict = match.NoMatch
		s.eng.onNoMatch(s)
	}
}

func (s *streamState) ReassemblyComplete(reassembly.AssemblerContext) bool {
	s.eng.onComplete(s)
	return true
}
