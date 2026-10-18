// Package testgenpcap builds the checked-in testdata/*.pcap fixtures and
// reads them back in the tests that replay them. The fixtures are the
// user-visible contract of whole-flow tests: open one in Wireshark to see the
// scenario a test exercises. Regenerate (and refresh the sha256 manifest)
// with `go run ./test` from the repo root; the drift test in this package
// pins file, manifest, and generator output to each other.
package testgenpcap

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"
)

// Well-known header sizes. Tests assert on slices of frames a builder just
// returned; naming these beats remembering that Ethernet is 14 bytes, IPv4
// is 20, IPv6 is 40.
const (
	EthHdrLen  = 14
	IPv4HdrLen = 20
	IPv6HdrLen = 40
	TCPHdrLen  = 20
)

// Epoch is the fixed first-packet time of every fixture. Deterministic
// timestamps keep regeneration byte-identical and the sha256 manifest
// meaningful; tests must not use the wall clock.
var Epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// ms returns the timestamp i milliseconds after Epoch.
func ms(i int64) time.Time { return Epoch.Add(time.Duration(i) * time.Millisecond) }

var (
	cliMAC = []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srvMAC = []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
)

func ips(s string) net.IP { return net.ParseIP(s) }

// TLSCH is a minimal ClientHello record carrying sni, from the cmd/cap tests.
func TLSCH(sni string) []byte {
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	body.Write(make([]byte, 32))
	body.WriteByte(0)
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01})
	body.WriteByte(1)
	body.WriteByte(0)

	var sniList bytes.Buffer
	sniList.WriteByte(0)
	binary.Write(&sniList, binary.BigEndian, uint16(len(sni)))
	sniList.WriteString(sni)
	var ext bytes.Buffer
	binary.Write(&ext, binary.BigEndian, uint16(0))
	binary.Write(&ext, binary.BigEndian, uint16(sniList.Len()+2))
	binary.Write(&ext, binary.BigEndian, uint16(sniList.Len()))
	ext.Write(sniList.Bytes())
	binary.Write(&body, binary.BigEndian, uint16(ext.Len()))
	body.Write(ext.Bytes())

	var hs bytes.Buffer
	hs.WriteByte(1)
	hs.Write([]byte{0, byte(body.Len() >> 8), byte(body.Len())})
	hs.Write(body.Bytes())

	var rec bytes.Buffer
	rec.WriteByte(22)
	rec.Write([]byte{0x03, 0x01})
	binary.Write(&rec, binary.BigEndian, uint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

// IPv4TCP is a bare IPv4/TCP packet (no link header), checksums zeroed. The
// engine reassembles on seq/ack order alone, so leaving them out keeps the
// builders honest about what they do not model.
func IPv4TCP(src, dst net.IP, sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	ip := make([]byte, IPv4HdrLen)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(IPv4HdrLen+TCPHdrLen+len(payload)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], src.To4())
	copy(ip[16:20], dst.To4())
	tcp := make([]byte, TCPHdrLen)
	binary.BigEndian.PutUint16(tcp[:2], sp)
	binary.BigEndian.PutUint16(tcp[2:4], dp)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4 // data offset (TCPHdrLen/4 = 5, no options)
	tcp[13] = flags
	return append(append(ip, tcp...), payload...)
}

// IPv6TCP is IPv4TCP for an IPv6 packet.
func IPv6TCP(src, dst net.IP, sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	ip6 := make([]byte, IPv6HdrLen)
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(TCPHdrLen+len(payload)))
	ip6[6] = 6
	ip6[7] = 64
	copy(ip6[8:24], src.To16())
	copy(ip6[24:40], dst.To16())
	tcp := make([]byte, TCPHdrLen)
	binary.BigEndian.PutUint16(tcp[:2], sp)
	binary.BigEndian.PutUint16(tcp[2:4], dp)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	return append(append(ip6, tcp...), payload...)
}

// wrapIn6 puts inner (a bare IPv4 or IPv6 packet) behind an IPv6 header with
// protocol nh (4=IPv4, 41=IPv6 per RFC 2473).
func wrapIn6(nh uint8, src6, dst6 net.IP, inner []byte) []byte {
	ip6 := make([]byte, IPv6HdrLen)
	ip6[0] = 0x60
	binary.BigEndian.PutUint16(ip6[4:6], uint16(len(inner)))
	ip6[6] = nh
	ip6[7] = 64
	copy(ip6[8:24], src6.To16())
	copy(ip6[24:40], dst6.To16())
	return append(ip6, inner...)
}

// IPv6 is a bare IPv6 packet with next-header nh around payload. It exposes
// the nh knob wrapIn6 hardcodes for tests that want non-L4 payloads (the
// internal/unpack tunnels) without rewriting the L4 builders.
func IPv6(nh uint8, src, dst net.IP, payload []byte) []byte {
	return wrapIn6(nh, src, dst, payload)
}

// CH is a ClientHello record with SNI and, if ech, an outer ECH extension
// (X25519-sized enc, 48-byte payload). It is buildCH from the engine tests,
// moved so engine can share it.
func CH(sni string, ech bool) []byte {
	ext := func(typ uint16, body []byte) []byte {
		b := binary.BigEndian.AppendUint16(nil, typ)
		b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
		return append(b, body...)
	}
	entry := append([]byte{0}, binary.BigEndian.AppendUint16(nil, uint16(len(sni)))...)
	entry = append(entry, sni...)
	list := binary.BigEndian.AppendUint16(nil, uint16(len(entry)))
	exts := ext(0, append(list, entry...))
	if ech {
		b := []byte{0, 0, 1, 0, 1, 0x42} // outer, kdf 1, aead 1, config_id
		b = binary.BigEndian.AppendUint16(b, 32)
		b = append(b, make([]byte, 32)...)
		b = binary.BigEndian.AppendUint16(b, 48)
		b = append(b, make([]byte, 48)...)
		exts = append(exts, ext(0xfe0d, b)...)
	}

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)                // session_id len
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(exts)))
	body = append(body, exts...)

	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{22, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

// Eth frames l3 on Ethernet between srvMAC and cliMAC with the given
// EtherType (0x0800 IPv4, 0x86dd IPv6).
func Eth(srcMAC, dstMAC []byte, etherType uint16, l3 []byte) []byte {
	var b bytes.Buffer
	b.Write(dstMAC)
	b.Write(srcMAC)
	binary.Write(&b, binary.BigEndian, etherType)
	b.Write(l3)
	return b.Bytes()
}

// EthIPv4 is an Ethernet+IPv4+TCP frame between the fixture MACs.
func EthIPv4(src, dst net.IP, sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return Eth(cliMAC, srvMAC, 0x0800, IPv4TCP(src, dst, sp, dp, seq, ack, flags, payload))
}

// Eth6in4 is an Ethernet+IPv6(NextHeader 4) frame carrying an inner IPv4/TCP
// packet, i.e. a 4-in-6 tunnel.
func Eth6in4(src6, dst6, src4, dst4 net.IP, sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return Eth(cliMAC, srvMAC, 0x86dd, wrapIn6(4, src6, dst6, IPv4TCP(src4, dst4, sp, dp, seq, ack, flags, payload)))
}

// Eth6in6 is Eth6in4 for two levels of IPv6 (NextHeader 41).
func Eth6in6(src6o, dst6o, src6i, dst6i net.IP, sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return Eth(cliMAC, srvMAC, 0x86dd, wrapIn6(41, src6o, dst6o, IPv6TCP(src6i, dst6i, sp, dp, seq, ack, flags, payload)))
}
