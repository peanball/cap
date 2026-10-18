package match

import (
	"net/netip"
	"sync/atomic"
)

// StreamInfo describes the stream being matched, passed to KeyMatchers.
// Populated by the engine at stream-creation time.
type StreamInfo struct {
	// IsTunneled reports whether packets arrived encapsulated (e.g. 4-in-6
	// 4-in-6 or 6-in-6). Tunneled streams have both Outer* (tunnel) and plain fields;
	// non-tunneled ones have only Outer* set, with Tunneled = false.
	IsTunneled bool

	// Outer 5-tuple as seen on the wire (for tunneled traffic, this is the
	// tunnel header's addresses).
	OuterSrcIP   netip.Addr
	OuterDstIP   netip.Addr
	OuterSrcPort uint16
	OuterDstPort uint16

	// Inner ports for tunneled TCP. Zero on non-TCP tunnels.
	// For non-tunneled streams this matches Outer ports.
	InnerSrcPort uint16
	InnerDstPort uint16

	// seenTunnel is set by the engine lazily; matchers MUST NOT gate on it
	// before IsTunneled is populated. Use IsTunneled.
	seen uint32 // atomic
}

// MarkSeenTunnel makes IsTunneled visible to consumers. Called once by the
// engine when the first tunnel packet arrives.
func (s *StreamInfo) MarkSeenTunnel() { atomic.StoreUint32(&s.seen, 1) }

// KeyMatcher inspects a stream's identity (IPs, ports, tunneled-ness).
// Consider is called once per stream after the engine populates StreamInfo.
// Returning false drops the stream: byte matchers never run.
//
// AND semantics: when KeyMatcher(s) are configured, a stream must pass ALL
// of them before byte matchers (SNI, PROXY) are evaluated.
type KeyMatcher interface {
	ConsiderKey(info *StreamInfo) bool
}

// TunnelIP matches streams that (a) ARE tunneled and (b) whose outer
// tunnel endpoint IPs fall within any of the listed CIDRs. One CIDR
// matching either src or dst is sufficient.
type TunnelIP struct {
	cidrs []netip.Prefix
}

func NewTunnelIP(cidrs []netip.Prefix) *TunnelIP { return &TunnelIP{cidrs: cidrs} }

func (t *TunnelIP) ConsiderKey(info *StreamInfo) bool {
	if !info.IsTunneled {
		return false
	}
	for _, c := range t.cidrs {
		if c.Contains(info.OuterSrcIP) || c.Contains(info.OuterDstIP) {
			return true
		}
	}
	return false
}

// TunnelPort matches streams that (a) ARE tunneled and (b) whose INNER src
// or dst port equals any of the listed ports.
type TunnelPort struct {
	ports map[uint16]struct{}
}

func NewTunnelPort(ports []uint16) *TunnelPort {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	return &TunnelPort{ports: m}
}

func (t *TunnelPort) ConsiderKey(info *StreamInfo) bool {
	if !info.IsTunneled {
		return false
	}
	if _, ok := t.ports[info.InnerSrcPort]; ok {
		return true
	}
	if _, ok := t.ports[info.InnerDstPort]; ok {
		return true
	}
	return false
}
