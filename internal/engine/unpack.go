package engine

// Unpack support: per-connection PROXY state and the single emit point for
// packets of kept connections. Enabled by Config.Unpack; when it is off the
// only cost is e.cfg.Unpack checks on the emit path.
//
// PROXY unpacking needs three things for each kept connection:
//   - whether the client→server stream starts with a PROXY header and how
//     long it is (learned from the buffered prefix in onMatch)
//   - which direction packets go (client vs server tuples)
//   - where a packet's payload sits in the stream (client SYN ISN)
// The last two are captured from the first packet of the connection, which
// is what a client SYN is expected to be. Everything is recorded by packet
// inspection in Process, so the assembler stays optional for matched conn
// tracking.

import (
	"net/netip"
	"time"

	"github.com/gopacket/gopacket/layers"

	"go.peanball.net/cap/internal/proxyhdr"
	"go.peanball.net/cap/internal/unpack"
)

// proxyTrack is one connection's PROXY unpack state.
type proxyTrack struct {
	csrc, cdst netip.Addr // client→server IP tuple from the SYN
	csp, cdp   uint16     // and ports
	isn        uint32     // client's initial sequence number (wire Syn.Seq)

	// hdr and hdrEnd are set in onMatch when the buffered client prefix
	// parses as a PROXY header. hdrEnd is the stream offset just past it;
	// the client stream offset of a packet is seq-isn-1.
	hdr    proxyhdr.Info
	hdrEnd int64
	has    bool // hdr valid
}

// noteSYN records the connection's client-facing tuple for proxyTrack on
// the first packet of a NEW connection (when e.cfg.Unpack).
func (e *Engine) noteUnpack(key flowKey, srcIP, dstIP netip.Addr, tcp *layers.TCP) {
	if !tcp.SYN || tcp.ACK {
		return // only create on the first SYN packet
	}
	pt := &proxyTrack{
		csrc: srcIP, cdst: dstIP,
		csp: uint16(tcp.SrcPort), cdp: uint16(tcp.DstPort),
		isn: uint32(tcp.Seq),
	}
	if e.proxy == nil {
		e.proxy = map[flowKey]*proxyTrack{}
	}
	e.proxy[key] = pt
}

// emitPacket writes one packet of a kept connection: the verbatim frame,
// then any unpack copies (tunnel inner; PROXY rewrites). The verbatim frame
// always comes first, so output reads as two stacked views of the same
// on-wire byte sequence.
func (e *Engine) emitPacket(key flowKey, ts time.Time, data []byte) error {
	if err := e.writeRecord(ts, data); err != nil {
		return err
	}
	if !e.cfg.Unpack {
		return nil
	}
	if dup, ok := unpack.Tunnel(e.link, data); ok {
		if err := e.writeRecord(ts, dup); err != nil {
			return err
		}
	}
	pt := e.proxy[key]
	if pt != nil && pt.has {
		// A failed PROXY-rewrite dup drops the dup only; the verbatim outer
		// packet already went out above.
		if err := e.emitProxy(pt, ts, data); err != nil {
			return err
		}
	}
	return nil
}

// emitProxy writes a PROXY-rewritten copy of data for packets whose client
// or server payload lies past the PROXY header. No-op for header packets.
func (e *Engine) emitProxy(pt *proxyTrack, ts time.Time, data []byte) error {
	m, ok := unpack.ParseMeta(e.link, data)
	if !ok {
		return nil
	}
	var c2s bool
	switch {
	case m.SrcIP == pt.csrc && m.DstIP == pt.cdst && m.SrcPort == pt.csp && m.DstPort == pt.cdp:
		c2s = true
	case m.SrcIP == pt.cdst && m.DstIP == pt.csrc && m.SrcPort == pt.cdp && m.DstPort == pt.csp:
		c2s = false
	default:
		return nil // retransmission with weird tuple; no dup
	}
	if c2s {
		// Stream offset of this packet's payload: seq-isn-1 covers the SYN.
		if int64(m.Seq-pt.isn)-1 < pt.hdrEnd {
			return nil // still inside the PROXY header
		}
		// A data-bearing packet only; SYN/FIN have no payload to represent.
	}
	if m.PayloadLen == 0 {
		return nil // pure control packet (SYN-ACK, keepalive ACK); nothing to show
	}
	dup, ok := unpack.PROXY(e.link, data, pt.hdr, c2s)
	if !ok {
		return nil
	}
	return e.writeRecord(ts, dup)
}
