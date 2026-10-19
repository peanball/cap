package engine

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"go.peanball.net/cap/internal/match"
	"go.peanball.net/cap/internal/pcap"
	"go.peanball.net/cap/internal/testgenpcap"
	"go.peanball.net/cap/internal/wireconv"
)

// ipv6FragFH builds one 8-byte Fragment Header for a chain reassembling to
// nextHdr. off is the 8-byte-unit offset (RFC 8200 §4.5).
func ipv6FragFH(nextHdr byte, off uint16, more bool, ident uint32) []byte {
	fh := make([]byte, 8)
	fh[0] = nextHdr
	field := off << 3
	if more {
		field |= 1
	}
	binary.BigEndian.PutUint16(fh[2:4], field)
	binary.BigEndian.PutUint32(fh[4:8], ident)
	return fh
}

// ipv6Frame builds an Ethernet+IPv6 frame (no tunnel) whose payload is frag
// with a Fragment header.
func ipv6FragFrame(srcMAC, dstMAC []byte, src, dst net.IP, nextHdrOfInnerChain byte, off uint16, more bool, ident uint32, chunk []byte) []byte {
	fh := ipv6FragFH(nextHdrOfInnerChain, off, more, ident)
	frame := make([]byte, 40)
	frame[0] = 0x60
	binary.BigEndian.PutUint16(frame[4:6], wireconv.MustUint16(len(fh)+len(chunk)))
	frame[6] = 44
	frame[7] = 64
	copy(frame[8:24], src.To16())
	copy(frame[24:40], dst.To16())
	return testgenpcap.Eth(srcMAC, dstMAC, 0x86dd, append(append(frame, fh...), chunk...))
}

// TestIPv6FragmentsMatchThroughReassembly splits a ClientHello across two
// IPv6 fragments and keeps the stream only because Process defragments
// before TCP lookup. Pins the IPv6-side counterpart of IPv4 defrag above.
func TestIPv6FragmentsMatchThroughReassembly(t *testing.T) {
	srcMAC, dstMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	cli, srv := net.ParseIP("2001:db8::a"), net.ParseIP("2001:db8::b")
	cs, ds := uint16(51000), uint16(443)

	ch := testgenpcap.TLSCH("peanball.net")

	// Unfragmented SYN so the stream table entry exists before the
	// fragments land; gopacket decodes this chain IPv6 → TCP.
	syn := testgenpcap.Eth(srcMAC, dstMAC, 0x86dd,
		testgenpcap.IPv6(6, cli, srv, testgenpcapTCPOnly(cs, ds, 1000, 0, 0x02, nil)))

	// The fragment chain: bytes are (20-byte TCP hdr + CH) split at
	// offset 8 (in 8-byte units, offset 1 = byte 8).
	full := testgenpcapTCPOnly(cs, ds, 1001, 1, 0x18, ch)

	ident := uint32(0x4242)
	frag1 := ipv6FragFrame(srcMAC, dstMAC, cli, srv, 6, 0, true, ident, full[:8])
	frag2 := ipv6FragFrame(srcMAC, dstMAC, cli, srv, 6, 1, false, ident, full[8:])

	frames := [][]byte{syn, frag1, frag2}

	sniM, err := match.NewSNI([]string{"peanball.net"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng, err := New(Config{Matcher: sniM},
		pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t0 := time.Unix(1700000000, 0)
	for i, f := range frames {
		if err := eng.Process(pcap.LinkEthernet, t0.Add(time.Duration(i)*time.Millisecond), f); err != nil {
			t.Fatalf("Process %d: %v", i, err)
		}
	}
	if got := eng.Stats().StreamsKept; got != 1 {
		t.Errorf("StreamsKept = %d, want 1 (CH visible only after IPv6 defrag)", got)
	}
}

// TestTunnelInnerIPv6Defrag wraps a fragmented inner-IPv6 datagram inside an
// unfragmented outer-IPv6 tunnel. Without inner defrag, the tunnel peel
// sees only a Fragment header and never the TCP+CH underneath; with defrag
// the stream matches and is kept.
func TestTunnelInnerIPv6Defrag(t *testing.T) {
	srcMAC, dstMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	outerSrc, outerDst := net.ParseIP("2001:db8::a"), net.ParseIP("2001:db8::b")
	innerSrc, innerDst := net.ParseIP("fd00::1"), net.ParseIP("fd00::2")
	cs, ds := uint16(51000), uint16(443)

	ch := testgenpcap.TLSCH("peanball.net")

	// Unfragmented inner SYN (inner TCP only, wrapped in inner IPv6, wrapped
	// in outer IPv6 / Ethernet).
	synInner := testgenpcapTCPOnly(cs, ds, 1000, 0, 0x02, nil)
	synInnerIPv6 := testgenpcap.IPv6(6, innerSrc, innerDst, synInner)
	syn := testgenpcap.Eth(srcMAC, dstMAC, 0x86dd,
		testgenpcap.IPv6(41, outerSrc, outerDst, synInnerIPv6))

	// The tunneled CH: (TCP hdr + CH) split in two fragments.
	full := testgenpcapTCPOnly(cs, ds, 1001, 1, 0x18, ch)

	ident := uint32(0x9a9a)
	var fragFrames [][]byte
	for i, chunk := range [][]byte{full[:8], full[8:]} {
		last := i == 1
		fh := ipv6FragFH(6, uint16(i), !last, ident)
		// Inner IPv6 carries the fragment header + chunk.
		innerIPv6 := make([]byte, 40)
		innerIPv6[0] = 0x60
		binary.BigEndian.PutUint16(innerIPv6[4:6], wireconv.MustUint16(len(fh)+len(chunk)))
		innerIPv6[6] = 44 // inner's NextHeader = Fragment
		innerIPv6[7] = 64
		copy(innerIPv6[8:24], innerSrc.To16())
		copy(innerIPv6[24:40], innerDst.To16())
		inner := append(append(innerIPv6, fh...), chunk...)
		// Outer IPv6 carries the whole inner.
		fragFrames = append(fragFrames, testgenpcap.Eth(srcMAC, dstMAC, 0x86dd,
			testgenpcap.IPv6(41, outerSrc, outerDst, inner)))
	}

	frames := append([][]byte{syn}, fragFrames...)

	sniM, err := match.NewSNI([]string{"peanball.net"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng, err := New(Config{Matcher: sniM},
		pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t0 := time.Unix(1700000000, 0)
	for i, f := range frames {
		if err := eng.Process(pcap.LinkEthernet, t0.Add(time.Duration(i)*time.Millisecond), f); err != nil {
			t.Fatalf("Process %d: %v", i, err)
		}
	}
	if got := eng.Stats().StreamsKept; got != 1 {
		t.Errorf("StreamsKept = %d, want 1 (tunneled inner CH visible only after inner IPv6 defrag)", got)
	}
}

// TestTunnelInnerIPv4Defrag matches a 4-in-6 tunnel whose inner IPv4
// datagrams are themselves fragmented.
func TestTunnelInnerIPv4Defrag(t *testing.T) {
	srcMAC, dstMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	cli6, srv6 := net.ParseIP("2001:db8::a"), net.ParseIP("2001:db8::b")
	cli4, srv4 := net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")
	cs, ds := uint16(51000), uint16(443)

	ch := testgenpcap.TLSCH("peanball.net")

	// Unfragmented SYN through the tunnel.
	syn := testgenpcap.Eth6in4(cli6, srv6, cli4, srv4, cs, ds, 1000, 0, 0x02, nil)

	// Fragmented inner-IPv4 packet carrying (TCP hdr + CH).
	full := testgenpcapTCPOnly(cs, ds, 1001, 1, 0x18, ch)

	ident := uint16(0x7777)
	var fragFrames [][]byte
	for i, chunk := range [][]byte{full[:8], full[8:]} {
		last := i == 1
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], wireconv.MustUint16(20+len(chunk)))
		binary.BigEndian.PutUint16(ip[4:6], ident)
		off := uint16(i)
		if !last {
			off |= 1 << 13
		}
		binary.BigEndian.PutUint16(ip[6:8], off)
		ip[8] = 64
		ip[9] = 6
		copy(ip[12:16], cli4.To4())
		copy(ip[16:20], srv4.To4())
		inner := append(ip, chunk...)

		fragFrames = append(fragFrames, testgenpcap.Eth(srcMAC, dstMAC, 0x86dd,
			testgenpcap.IPv6(4, cli6, srv6, inner)))
	}

	frames := append([][]byte{syn}, fragFrames...)

	sniM, err := match.NewSNI([]string{"peanball.net"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng, err := New(Config{Matcher: sniM},
		pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t0 := time.Unix(1700000000, 0)
	for i, f := range frames {
		if err := eng.Process(pcap.LinkEthernet, t0.Add(time.Duration(i)*time.Millisecond), f); err != nil {
			t.Fatalf("Process %d: %v", i, err)
		}
	}
	if got := eng.Stats().StreamsKept; got != 1 {
		t.Errorf("StreamsKept = %d, want 1 (4-in-6 inner CH visible only after inner IPv4 defrag)", got)
	}
}

// testgenpcapTCPOnly is IPv4TCP's TCP half: 20-byte header+payload, no IP.
// Used when a packet is the tunnel's inner — the outer IPv6's payload.
func testgenpcapTCPOnly(sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return testgenpcap.IPv4TCP(net.IPv4zero, net.IPv4zero, sp, dp, seq, ack, flags, payload)[20:]
}
