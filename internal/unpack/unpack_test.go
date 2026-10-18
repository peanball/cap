package unpack

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"go.peanball.net/cap/internal/pcap"
	"go.peanball.net/cap/internal/proxyhdr"
	"go.peanball.net/cap/internal/testgenpcap"
)

var (
	testMACSrc = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	testMACDst = []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
)

// mkEth builds an Ethernet frame around payload with the given ethertype.
// Delegates to testgenpcap.Eth between the fixed test MACs.
func mkEth(t *testing.T, et uint16, payload []byte) []byte {
	t.Helper()
	return testgenpcap.Eth(testMACSrc, testMACDst, et, payload)
}

// mkIPv4TCP builds a minimal IPv4/TCP packet (no options), checksums zeroed.
// Ack is always 0 — these are unit-level dup tests, not reassembly scenarios.
func mkIPv4TCP(v4src, v4dst net.IP, sp, dp uint16, seq uint32, flags uint8, payload []byte) []byte {
	return testgenpcap.IPv4TCP(v4src, v4dst, sp, dp, seq, 0, flags, payload)
}

// mkIPv6 builds an IPv6 header with next-header nh around payload.
func mkIPv6(src, dst net.IP, nh uint8, payload []byte) []byte {
	return testgenpcap.IPv6(nh, src, dst, payload)
}

func TestTunnelDupReframesOnOuterLink(t *testing.T) {
	src6, dst6 := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	inner := mkIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1234, 443, 100, 0x18, []byte("hi"))
	outer := mkEth(t, 0x86dd, mkIPv6(src6, dst6, 4, inner))
	orig := append([]byte(nil), outer...)

	dup, ok := Tunnel(pcap.LinkEthernet, outer)
	if !ok {
		t.Fatal("not recognized as tunneled")
	}
	if !bytes.Equal(outer, orig) {
		t.Error("outer packet modified")
	}
	if bytes.Equal(dup, orig) {
		t.Error("dup equals outer frame")
	}
	if !bytes.Equal(dup[:12], orig[:12]) {
		t.Error("dup lost the link header's address part")
	}
	if got := binary.BigEndian.Uint16(dup[12:14]); got != 0x0800 {
		t.Errorf("dup protocol field = 0x%04x, want 0x0800", got)
	}
	if !bytes.Equal(dup[14:], inner) {
		t.Error("dup is not the inner IPv4 packet")
	}
	// Tunnel must not touch its input.
	if !bytes.Equal(outer, orig) {
		t.Error("Tunnel modified its input")
	}
}

// TestTunnelDup6in6 checks the nested-IPv6 variant: the dup keeps the outer
// link header, gets protocol field 0x86dd, and carries the inner IPv6
// packet (with its TCP payload) unchanged.
func TestTunnelDup6in6(t *testing.T) {
	o6a, o6b := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	i6a, i6b := net.ParseIP("fd00::1"), net.ParseIP("fd00::2")
	innerTCP := mkIPv4TCP(net.ParseIP("0.0.0.0"), net.ParseIP("0.0.0.0"), 1234, 443, 100, 0x18, []byte("hi"))[20:]
	inner := mkIPv6(i6a, i6b, 6, innerTCP)
	outer := mkEth(t, 0x86dd, mkIPv6(o6a, o6b, 41, inner))
	orig := append([]byte(nil), outer...)

	dup, ok := Tunnel(pcap.LinkEthernet, outer)
	if !ok {
		t.Fatal("not recognized as tunneled")
	}
	if !bytes.Equal(outer, orig) {
		t.Error("outer packet modified")
	}
	if !bytes.Equal(dup[:12], orig[:12]) {
		t.Error("dup lost the link header's address part")
	}
	if got := binary.BigEndian.Uint16(dup[12:14]); got != 0x86dd {
		t.Errorf("dup protocol field = 0x%04x, want 0x86dd", got)
	}
	if !bytes.Equal(dup[14:], inner) {
		t.Error("dup is not the inner IPv6 packet")
	}
	// Wrong mix: NextHeader says IPv4 but payload starts with a v6 header.
	bad := mkEth(t, 0x86dd, mkIPv6(o6a, o6b, 4, inner))
	if _, ok := Tunnel(pcap.LinkEthernet, bad); ok {
		t.Error("NextHeader 4 with IPv6 payload accepted")
	}
}

func TestTunnelNoDupForPlainAndRaw(t *testing.T) {
	plain := mkEth(t, 0x0800, mkIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2, 0, 0x02, nil))
	if _, ok := Tunnel(pcap.LinkEthernet, plain); ok {
		t.Error("plain IPv4 frame reported tunneled")
	}
	inner := mkIPv4TCP(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2, 0, 0x02, nil)
	raw6 := mkIPv6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 4, inner)
	for _, lt := range []pcap.LinkType{pcap.LinkIPv6, pcap.LinkRaw} {
		if dup, ok2 := Tunnel(lt, raw6); ok2 || dup != nil {
			t.Errorf("link %v: dup on a link type without ethertype", lt)
		}
	}
	// IPv6 frame carrying TCP (not 4-in-6) on Ethernet: no dup.
	plain6 := mkEth(t, 0x86dd, mkIPv6(net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 6, mkIPv4TCP(net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), 1, 2, 0, 0x02, nil)[20:]))
	if _, ok := Tunnel(pcap.LinkEthernet, plain6); ok {
		t.Error("plain IPv6 TCP frame reported tunneled")
	}
}

// mkProxyInfo returns a PROXY v1-header info for the given addresses.
func proxyInfo(src, dst string, sp, dp uint16, l int) proxyhdr.Info {
	s := netip.MustParseAddr(src)
	d := netip.MustParseAddr(dst)
	return proxyhdr.Info{Version: proxyhdr.VersionV1, SrcIP: s, DstIP: d, SrcPort: sp, DstPort: dp, Length: l}
}

func TestProxyDupRewritesTupleAndFixesChecksums(t *testing.T) {
	// Captured: proxy(192.0.2.1:4321) → client(10.0.0.5:54802). PROXY says
	// the real client is 192.0.2.99:4321 talking to 192.0.2.1:4321... simplified:
	info := proxyInfo("192.0.2.99", "192.0.2.1", 4321, 4321, 47)
	frame := mkEth(t, 0x0800, mkIPv4TCP(net.ParseIP("10.0.0.5"), net.ParseIP("192.0.2.1"), 54802, 4321, 700, 0x18, []byte("GET /")))
	orig := append([]byte(nil), frame...)

	dup, ok := PROXY(pcap.LinkEthernet, frame, info, true)
	if !ok {
		t.Fatal("no dup")
	}
	if !bytes.Equal(frame, orig) {
		t.Error("PROXY modified its input")
	}
	dup = dup[14:] // strip link
	sip, _ := netip.AddrFromSlice(dup[12:16])
	dip, _ := netip.AddrFromSlice(dup[16:20])
	if sip.String() != "192.0.2.99" || dip.String() != "192.0.2.1" {
		t.Errorf("dup addresses %s->%s", sip, dip)
	}
	if got := binary.BigEndian.Uint16(dup[20:22]); got != 4321 {
		t.Errorf("dup src port %d, want 4321", got)
	}
	if got := binary.BigEndian.Uint16(dup[22:24]); got != 4321 {
		t.Errorf("dup dst port %d, want 4321 (tuple from header)", got)
	}
	// Total length is consistent with the payload.
	if got := binary.BigEndian.Uint16(dup[2:4]); int(got) != len(dup) {
		t.Errorf("IPv4 length %d, dup wire %d", got, len(dup))
	}
	// Header checksum must validate (sum over header = 0xffff).
	if got := headerSum(dup[:20]); got != 0 {
		t.Errorf("IPv4 header checksum invalid: fold = %#x", got)
	}
	// TCP checksum must validate with pseudo-header.
	if got := tcpSum(dup[:20], dup[20:]); got != 0 {
		t.Errorf("TCP checksum invalid: fold = %#x", got)
	}
	// Seq/flags/payload survive.
	if binary.BigEndian.Uint32(dup[24:28]) != 700 || dup[33] != 0x18 {
		t.Error("seq/flags not preserved")
	}
	if !bytes.Equal(dup[40:], []byte("GET /")) {
		t.Error("payload altered")
	}
}

func TestProxyDupSkips(t *testing.T) {
	info := proxyInfo("192.0.2.99", "192.0.2.1", 4321, 4321, 47)
	// IPv6 packet with v4 header tuple → no dup.
	v6 := mkEth(t, 0x86dd, mkIPv6(net.ParseIP("2001:db8::5"), net.ParseIP("2001:db8::1"), 6, mkIPv4TCP(net.ParseIP("1.1.1.1"), net.ParseIP("2.2.2.2"), 1, 2, 0, 0x02, nil)[20:]))
	if _, ok := PROXY(pcap.LinkEthernet, v6, info, true); ok {
		t.Error("v4 tuple packed onto v6 frame")
	}
	// UNKNOWN (no addrs) → no dup.
	unk := proxyhdr.Info{Version: proxyhdr.VersionV1, Length: 15}
	if _, ok := PROXY(pcap.LinkEthernet, mkEth(t, 0x0800, mkIPv4TCP(net.ParseIP("10.0.0.5"), net.ParseIP("10.0.0.6"), 1, 2, 0, 0x02, nil)), unk, true); ok {
		t.Error("dup made for PROXY UNKNOWN")
	}
}

// tcpSum evaluates the TCP checksum (must fold to 0 on a correct packet).
func tcpSum(iph, seg []byte) uint16 {
	var s uint32
	s += uint32(binary.BigEndian.Uint16(iph[12:14]))
	s += uint32(binary.BigEndian.Uint16(iph[14:16]))
	s += uint32(binary.BigEndian.Uint16(iph[16:18]))
	s += uint32(binary.BigEndian.Uint16(iph[18:20]))
	s += uint32(iph[9])
	s += uint32(len(seg))
	for len(seg) > 1 {
		s += uint32(binary.BigEndian.Uint16(seg[:2]))
		seg = seg[2:]
	}
	if len(seg) == 1 {
		s += uint32(seg[0]) << 8
	}
	return fold(s)
}
