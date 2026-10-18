package proxyhdr

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func TestV1TCP4(t *testing.T) {
	buf := []byte("PROXY TCP4 203.0.113.7 198.51.100.4 43125 443\r\n")
	info, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.Version != VersionV1 {
		t.Errorf("Version = %v want V1", info.Version)
	}
	if info.SrcIP != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("SrcIP = %v", info.SrcIP)
	}
	if info.DstIP != netip.MustParseAddr("198.51.100.4") {
		t.Errorf("DstIP = %v", info.DstIP)
	}
	if info.SrcPort != 43125 || info.DstPort != 443 {
		t.Errorf("ports = %d/%d", info.SrcPort, info.DstPort)
	}
	if info.Length != len(buf) {
		t.Errorf("Length = %d want %d", info.Length, len(buf))
	}
}

func TestV1TCP6(t *testing.T) {
	buf := []byte("PROXY TCP6 2001:db8::1 2001:db8::2 1234 80\r\n")
	info, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SrcIP != netip.MustParseAddr("2001:db8::1") {
		t.Errorf("SrcIP = %v", info.SrcIP)
	}
}

func TestV1Unknown(t *testing.T) {
	info, err := Parse([]byte("PROXY UNKNOWN\r\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SrcIP.IsValid() {
		t.Errorf("SrcIP should be zero on UNKNOWN, got %v", info.SrcIP)
	}
}

func TestV1NeedMore(t *testing.T) {
	full := []byte("PROXY TCP4 1.1.1.1 2.2.2.2 100 200\r\n")
	for i := 0; i < len(full); i++ {
		_, err := Parse(full[:i])
		if !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix %d: want ErrNeedMore, got %v", i, err)
		}
	}
}

func TestV1NotProxy(t *testing.T) {
	cases := [][]byte{
		[]byte("GET / HTTP/1.1\r\n"),
		[]byte("PROXY FOO\r\n"),                          // unknown proto tag without UNKNOWN
		[]byte("PROXY TCP4 999.1.1.1 2.2.2.2 1 2\r\n"),   // bad IP
		[]byte("PROXY TCP4 1.1.1.1 2.2.2.2 99999 2\r\n"), // bad port
	}
	for i, c := range cases {
		if _, err := Parse(c); !errors.Is(err, ErrNotProxy) {
			t.Errorf("case %d: want ErrNotProxy, got %v", i, err)
		}
	}
}

// buildV2 constructs a v2 header for TCP4.
func buildV2(src, dst string, sport, dport uint16) []byte {
	s := netip.MustParseAddr(src).As4()
	d := netip.MustParseAddr(dst).As4()
	buf := make([]byte, 16+12)
	copy(buf[:12], []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a})
	buf[12] = 0x21 // ver=2, cmd=PROXY
	buf[13] = 0x11 // fam=IPv4, proto=STREAM
	buf[14] = 0
	buf[15] = 12
	copy(buf[16:20], s[:])
	copy(buf[20:24], d[:])
	buf[24] = byte(sport >> 8)
	buf[25] = byte(sport)
	buf[26] = byte(dport >> 8)
	buf[27] = byte(dport)
	return buf
}

func TestV2TCP4(t *testing.T) {
	buf := buildV2("10.0.0.1", "10.0.0.2", 5555, 8080)
	info, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.Version != VersionV2 {
		t.Errorf("Version = %v want V2", info.Version)
	}
	if info.SrcIP != netip.MustParseAddr("10.0.0.1") || info.DstIP != netip.MustParseAddr("10.0.0.2") {
		t.Errorf("IPs = %v -> %v", info.SrcIP, info.DstIP)
	}
	if info.SrcPort != 5555 || info.DstPort != 8080 {
		t.Errorf("ports = %d/%d", info.SrcPort, info.DstPort)
	}
	if info.Length != 28 {
		t.Errorf("Length = %d want 28", info.Length)
	}
}

func TestV2Local(t *testing.T) {
	buf := buildV2("1.1.1.1", "2.2.2.2", 1, 2)
	buf[12] = 0x20 // LOCAL command
	info, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse LOCAL: %v", err)
	}
	if info.SrcIP.IsValid() {
		t.Errorf("LOCAL should carry no client info, got %v", info.SrcIP)
	}
}

func TestV2NeedMore(t *testing.T) {
	full := buildV2("10.0.0.1", "10.0.0.2", 1, 2)
	for i := 0; i < len(full); i++ {
		_, err := Parse(full[:i])
		if !errors.Is(err, ErrNeedMore) {
			t.Fatalf("prefix %d: want ErrNeedMore, got %v", i, err)
		}
	}
}

func TestV2WithTLVs(t *testing.T) {
	base := buildV2("10.0.0.1", "10.0.0.2", 1, 2)
	// Append a TLV of 5 bytes after the 12-byte addr.
	tlv := []byte{0x01, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'}
	buf := append(base, tlv...)
	buf[15] = 12 + uint8(len(tlv))
	info, err := Parse(buf)
	if err != nil {
		t.Fatalf("Parse with TLVs: %v", err)
	}
	if info.Length != len(buf) {
		t.Errorf("Length = %d want %d (TLVs counted)", info.Length, len(buf))
	}
}

func TestV1SurvivesV2PrefixCheck(t *testing.T) {
	// V1 text and V2 magic diverge at byte 0; ensure we don't accidentally
	// claim NeedMore on a V1 line.
	if !bytes.HasPrefix([]byte("PROXY "), []byte("PROXY ")) {
		t.Fatal("test sanity")
	}
	_, err := Parse([]byte("PROXY "))
	if !errors.Is(err, ErrNeedMore) {
		t.Errorf("partial PROXY v1 prefix should yield NeedMore, got %v", err)
	}
}
