// Package unpack emits copies of packets with the parts of a stream's
// envelope made explicit, for tools that look at one packet at a time.
//
// Two kinds are supported, both opt-in and applied only to kept streams:
//
// Tunneling (IPv4-in-IPv6, NextHeader 4): in addition to the outer packet, a
// copy of the inner packet is emitted on the outer link layer, with the
// link layer's protocol field rewritten to IPv4. The outer is always
// emitted verbatim. Dups require a link layer with a protocol field
// (Ethernet, Linux SLL, SLL2); on raw IPv4/IPv6 captures there is no place
// for a dup and none is made.
//
// PROXY protocol (v1, v2): after the header has been seen on the client
// side of a kept connection, every later client packet gets a copy with the
// 5-tuple the header asserts (original client to frontend) and no PROXY
// bytes in it. Server-side copies get the reverse. The original packets,
// including the one carrying the header, are emitted verbatim. PROXY
// UNKNOWN and address-family mismatches yield no copies.
//
// Sequences and flags are copied untouched; IP length fields and IPv4/TCP
// checksums are recomputed. Input frames are never modified.
package unpack

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"go.peanball.net/cap/internal/pcap"
	"go.peanball.net/cap/internal/proxyhdr"
)

var (
	// ErrNotTCP is returned when the frame carries no TCP over IPv4/IPv6.
	ErrNotTCP = errors.New("unpack: no TCP in frame")
)

// frame annotates one packet with offsets usable by rewriters.
type frame struct {
	link  pcap.LinkType
	raw   []byte // whole captured frame
	head  []byte // link header prefix (ethertype-bearing part we copy)
	ip    []byte // IP packet inside raw
	etOff int    // offset inside head of the 2-byte protocol field
	ihl   int    // IPv4 header length, or 40 for IPv6
	v4    bool
}

// netProto is the value stamped into the link protocol field.
const protoIPv4 = 0x0800

// protoIPv6 marks a dup carrying an inner IPv6 packet (6-in-6 tunnel).
const protoIPv6 = 0x86dd

// Meta is the decoded 5-tuple of one packet and its TCP sequence number.
type Meta struct {
	SrcIP, DstIP     netip.Addr
	SrcPort, DstPort uint16
	Seq              uint32 // TCP sequence at the packet's first byte
	PayloadLen       int    // TCP payload bytes in this capture
}

// ParseMeta decodes the outermost TCP packet of raw as link type link.
// ok=false for frames that carry no TCP (the caller just skips unpacking).
func ParseMeta(link pcap.LinkType, raw []byte) (Meta, bool) {
	link, _ = normalizeLink(link)
	f, err := decode(link, raw)
	if err != nil {
		return Meta{}, false
	}
	if !f.v4 && f.ip[6] != 6 {
		return Meta{}, false // tunneled (4 in 6 or 41 in 6): no outer TCP
	}
	tcp := f.ip[f.ihl:]
	if len(tcp) < 20 {
		return Meta{}, false
	}
	dataOff := int(tcp[12]>>4) * 4
	if dataOff < 20 || dataOff > len(tcp) {
		return Meta{}, false
	}
	m := Meta{
		SrcPort:    binary.BigEndian.Uint16(tcp[0:2]),
		DstPort:    binary.BigEndian.Uint16(tcp[2:4]),
		Seq:        binary.BigEndian.Uint32(tcp[4:8]),
		PayloadLen: len(tcp) - dataOff,
	}
	if f.v4 {
		m.SrcIP, _ = netip.AddrFromSlice(f.ip[12:16])
		m.DstIP, _ = netip.AddrFromSlice(f.ip[16:20])
	} else {
		m.SrcIP, _ = netip.AddrFromSlice(f.ip[8:24])
		m.DstIP, _ = netip.AddrFromSlice(f.ip[24:40])
	}
	return m, true
}

// decode inspects one captured frame.
func decode(link pcap.LinkType, raw []byte) (f frame, err error) {
	f = frame{link: link, raw: raw}
	var ipOff int
	switch link {
	case pcap.LinkEthernet:
		if len(raw) < 14+20 {
			return f, ErrNotTCP
		}
		f.etOff = 12
		et := binary.BigEndian.Uint16(raw[12:14])
		ipOff = 14
		if et == 0x8100 { // one 802.1Q tag
			if len(raw) < 18+20 {
				return f, ErrNotTCP
			}
			f.etOff = 16
			et = binary.BigEndian.Uint16(raw[16:18])
			ipOff = 18
		}
		if et != 0x0800 && et != 0x86dd {
			return f, ErrNotTCP
		}
		f.head = raw[:ipOff]
	case pcap.LinkLinuxSLL:
		if len(raw) < 16+20 {
			return f, ErrNotTCP
		}
		et := binary.BigEndian.Uint16(raw[14:16])
		if et != 0x0800 && et != 0x86dd {
			return f, ErrNotTCP
		}
		f.etOff = 14
		f.head = raw[:16]
		ipOff = 16
	case pcap.LinkLinuxSLL2:
		if len(raw) < 20+20 {
			return f, ErrNotTCP
		}
		et := binary.BigEndian.Uint16(raw[0:2])
		if et != 0x0800 && et != 0x86dd {
			return f, ErrNotTCP
		}
		f.etOff = 0
		f.head = raw[:20]
		ipOff = 20
	case pcap.LinkIPv4, pcap.LinkIPv6, pcap.LinkRaw:
		ipOff = 0 // no link header to copy; no protocol field to patch
	default:
		return f, ErrNotTCP
	}
	if ipOff >= len(raw) {
		return f, ErrNotTCP
	}
	ip := raw[ipOff:]
	f.ip = ip
	switch ip[0] >> 4 {
	case 4:
		f.v4 = true
		if len(ip) < 20 {
			return f, ErrNotTCP
		}
		f.ihl = int(ip[0]&0x0f) * 4
		if f.ihl < 20 || len(ip) < f.ihl+20 {
			return f, ErrNotTCP
		}
		if ip[9] != 6 {
			return f, ErrNotTCP
		}
	case 6:
		if len(ip) < 40 {
			return f, ErrNotTCP
		}
		f.ihl = 40
		// Directly carried TCP, or a tunneled IPv4 (4) / IPv6 (41) packet.
		if len(ip) < 60 && ip[6] != 4 && ip[6] != 41 {
			return f, ErrNotTCP
		}
		if ip[6] != 6 && ip[6] != 4 && ip[6] != 41 {
			return f, ErrNotTCP
		}
	default:
		return f, ErrNotTCP
	}
	return f, nil
}

// Tunnel returns a copy of the inner packet of an in-6 tunnel frame
// (IPv6 NextHeader 4 for IPv4, 41 for a nested IPv6), reframed on the outer
// link layer with its protocol field set to the inner version's value.
// Returns ok=false for non-tunneled frames and for link types without a
// protocol field (raw IPv4/IPv6 captures get no tunnel dups).
func Tunnel(link pcap.LinkType, raw []byte) (dup []byte, ok bool) {
	link, _ = normalizeLink(link)
	f, err := decode(link, raw)
	if err != nil {
		return nil, false
	}
	if f.v4 || (f.ip[6] != 4 && f.ip[6] != 41) {
		return nil, false
	}
	inner := f.ip[40:]
	var proto uint16
	switch v := inner[0] >> 4; v {
	case 4:
		if f.ip[6] != 4 || len(inner) < 20 {
			return nil, false
		}
		proto = protoIPv4
	case 6:
		if f.ip[6] != 41 || len(inner) < 40 {
			return nil, false
		}
		proto = protoIPv6
	default:
		return nil, false
	}
	// Raw link captures carry no protocol field to point at the dup.
	switch link {
	case pcap.LinkIPv4, pcap.LinkIPv6, pcap.LinkRaw:
		return nil, false
	}
	dup = make([]byte, 0, len(f.head)+len(inner))
	dup = append(dup, f.head...)
	binary.BigEndian.PutUint16(dup[f.etOff:], proto)
	dup = append(dup, inner...)
	return dup, true
}

// normalizeLink maps raw IPv6/IPv4 to LinkRaw semantics for decode: decode
// sniffs the version nibble itself on those.
func normalizeLink(link pcap.LinkType) (pcap.LinkType, bool) {
	switch link {
	case pcap.LinkIPv4, pcap.LinkIPv6:
		return pcap.LinkRaw, true
	default:
		return link, false
	}
}

// PROXY returns a copy of raw rewritten to the tuple info asserts. dir=true
// for client-to-server packets (they are written as SrcIP:SrcPort to
// DstIP:DstPort), dir=false for replies (tuple swapped). The frame's IP
// version must match the tuple's; on mismatch ok=false.
//
// The caller must only invoke this for packets whose payload lies entirely
// past the PROXY header; header-carrying packets are emitted verbatim.
func PROXY(link pcap.LinkType, raw []byte, info proxyhdr.Info, clientToServer bool) (dup []byte, ok bool) {
	if !info.SrcIP.IsValid() || !info.DstIP.IsValid() {
		return nil, false
	}
	link, _ = normalizeLink(link)
	f, err := decode(link, raw)
	if err != nil {
		return nil, false
	}
	if f.v4 != info.SrcIP.Is4() || f.v4 != info.DstIP.Is4() {
		return nil, false
	}
	srcIP, dstIP := info.SrcIP, info.DstIP
	sp, dp := info.SrcPort, info.DstPort
	if !clientToServer {
		srcIP, dstIP = dstIP, srcIP
		sp, dp = dp, sp
	}

	// Build the copy: link head + IP packet.
	dup = make([]byte, 0, len(f.head)+len(f.ip))
	dup = append(dup, f.head...)
	ipOff := len(dup)
	dup = append(dup, f.ip...)
	ip := dup[ipOff:]

	if f.v4 {
		s := srcIP.As4()
		d := dstIP.As4()
		copy(ip[12:16], s[:])
		copy(ip[16:20], d[:])
	} else {
		s := srcIP.As16()
		d := dstIP.As16()
		copy(ip[8:24], s[:])
		copy(ip[24:40], d[:])
	}
	binary.BigEndian.PutUint16(ip[f.ihl:], sp)
	binary.BigEndian.PutUint16(ip[f.ihl+2:], dp)

	fixup(ip, f.v4, f.ihl)
	return dup, true
}

// fixup recomputes IP length fields, IPv4 header checksum (v4) and the TCP
// checksum of the (modified) packet ip.
func fixup(ip []byte, v4 bool, ihl int) {
	if v4 {
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		binary.BigEndian.PutUint16(ip[10:12], 0)
		binary.BigEndian.PutUint16(ip[10:12], headerSum(ip[:ihl]))
	} else {
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(ip)-40))
	}
	// TCP checksum over pseudo-header + segment.
	binary.BigEndian.PutUint16(ip[ihl+16:], 0)
	var s uint32
	if v4 {
		s += uint32(binary.BigEndian.Uint16(ip[12:14]))
		s += uint32(binary.BigEndian.Uint16(ip[14:16]))
		s += uint32(binary.BigEndian.Uint16(ip[16:18]))
		s += uint32(binary.BigEndian.Uint16(ip[18:20]))
		s += uint32(ip[9])
	} else {
		for i := 8; i < 40; i += 2 {
			s += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
		}
		s += uint32(ip[6])
	}
	s += uint32(len(ip) - ihl)
	seg := ip[ihl:]
	for len(seg) > 1 {
		s += uint32(binary.BigEndian.Uint16(seg[:2]))
		seg = seg[2:]
	}
	if len(seg) == 1 {
		s += uint32(seg[0]) << 8
	}
	sum := fold(s)
	if sum == 0 && !v4 {
		sum = 0xffff
	}
	binary.BigEndian.PutUint16(ip[ihl+16:], sum)
}

func headerSum(h []byte) uint16 {
	var s uint32
	for len(h) > 1 {
		s += uint32(binary.BigEndian.Uint16(h[:2]))
		h = h[2:]
	}
	return fold(s)
}

func fold(s uint32) uint16 {
	for s > 0xffff {
		s = (s >> 16) + (s & 0xffff)
	}
	return ^uint16(s)
}
