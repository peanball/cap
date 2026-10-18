// Package proxyhdr parses PROXY protocol headers (v1 text, v2 binary) from
// the start of a reassembled TCP stream. Both versions carry the original
// client src/dst addresses and ports placed by a fronting LB.
package proxyhdr

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
)

var (
	ErrNeedMore = errors.New("need more bytes")
	ErrNotProxy = errors.New("not a PROXY header")
)

// Version identifies the wire form.
type Version int

const (
	VersionNone Version = 0
	VersionV1   Version = 1
	VersionV2   Version = 2

	// VersionAny is a CLI flag value meaning either v1 or v2 matches.
	VersionAny Version = -1
)

// Info is the parsed PROXY header contents.
type Info struct {
	Version Version
	SrcIP   netip.Addr // original client
	DstIP   netip.Addr // proxy/LB
	SrcPort uint16
	DstPort uint16
	// Length is the total bytes consumed by the header itself (prefix on the
	// stream). Callers strip this many bytes before handing payload to any
	// subsequent matcher.
	Length int
}

var v2Magic = []byte{0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a}

// maxV1Len is the spec-capped v1 header length (107 bytes); we peek at
// most this before concluding no v1 header exists.
const maxV1Len = 107

// Parse inspects the start of buf for a PROXY header. It returns info and
// nil error on success; ErrNeedMore if buf might become a PROXY header
// with more bytes; ErrNotProxy if it can't ever be one.
func Parse(buf []byte) (Info, error) {
	// If the prefix is a prefix of the v2 magic (or vice versa), it's still
	// potentially v2. v1 "PROXY " and v2 magic diverge at byte 0, so any
	// non-empty buf decides which branch is possible.
	if len(buf) > 0 {
		b0 := buf[0]
		v1Possible := b0 == 'P'
		v2Possible := b0 == v2Magic[0]
		if v1Possible {
			if info, err := parseV1(buf); err == nil || !errors.Is(err, ErrNotProxy) {
				return info, err
			}
		}
		if v2Possible {
			if info, err := parseV2(buf); err == nil || !errors.Is(err, ErrNotProxy) {
				return info, err
			}
		}
		if !v1Possible && !v2Possible {
			return Info{}, ErrNotProxy
		}
		// Both branches returned NotProxy above, meaning buf is not a prefix
		// of either signature.
		return Info{}, ErrNotProxy
	}
	return Info{}, ErrNeedMore
}

// parseV1: "PROXY TCP4 SRC DST SPORT DPORT\r\n" or "PROXY TCP6 ..." or
// "PROXY UNKNOWN\r\n". Upper bound 107 bytes including CRLF.
func parseV1(buf []byte) (Info, error) {
	prefix := []byte("PROXY ")
	if len(buf) < len(prefix) {
		if bytes.HasPrefix(prefix, buf) {
			return Info{}, ErrNeedMore
		}
		return Info{}, ErrNotProxy
	}
	if !bytes.Equal(buf[:len(prefix)], prefix) {
		return Info{}, ErrNotProxy
	}
	// Look for CRLF within bounds.
	end := bytes.Index(buf, []byte("\r\n"))
	if end < 0 {
		if len(buf) >= maxV1Len {
			return Info{}, ErrNotProxy
		}
		return Info{}, ErrNeedMore
	}
	if end+2 > maxV1Len {
		return Info{}, ErrNotProxy
	}
	line := string(buf[len(prefix):end])
	fields := splitWS(line)
	if len(fields) < 1 {
		return Info{}, ErrNotProxy
	}
	info := Info{Version: VersionV1, Length: end + 2}
	switch fields[0] {
	case "UNKNOWN":
		return info, nil
	case "TCP4", "TCP6":
		if len(fields) != 5 {
			return Info{}, ErrNotProxy
		}
		src, err := netip.ParseAddr(fields[1])
		if err != nil {
			return Info{}, ErrNotProxy
		}
		dst, err := netip.ParseAddr(fields[2])
		if err != nil {
			return Info{}, ErrNotProxy
		}
		sp, err := parsePort(fields[3])
		if err != nil {
			return Info{}, ErrNotProxy
		}
		dp, err := parsePort(fields[4])
		if err != nil {
			return Info{}, ErrNotProxy
		}
		info.SrcIP, info.DstIP = src, dst
		info.SrcPort, info.DstPort = sp, dp
		return info, nil
	default:
		return Info{}, ErrNotProxy
	}
}

func parsePort(s string) (uint16, error) {
	p, err := strconv.ParseUint(s, 10, 16)
	return uint16(p), err
}

// splitWS avoids strings.Fields' alloc-heavy Unicode handling; PROXY v1 is
// strictly ASCII single-space-separated.
func splitWS(s string) []string {
	var out []string
	start := -1
	for i, c := range []byte(s) {
		if c == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
		} else if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

// parseV2: 16-byte header — magic(12) ver_cmd(1) fam_proto(1) len(2) —
// followed by `len` bytes of addresses (and TLVs, which we skip).
func parseV2(buf []byte) (Info, error) {
	if len(buf) < 12 {
		if len(buf) == 0 || bytes.HasPrefix(v2Magic[:len(buf)], buf) {
			return Info{}, ErrNeedMore
		}
		return Info{}, ErrNotProxy
	}
	if !bytes.Equal(buf[:12], v2Magic) {
		return Info{}, ErrNotProxy
	}
	if len(buf) < 16 {
		return Info{}, ErrNeedMore
	}
	verCmd := buf[12]
	if verCmd>>4 != 2 {
		return Info{}, ErrNotProxy
	}
	cmd := verCmd & 0x0f
	// cmd: 0x00 LOCAL (ignore addresses), 0x01 PROXY (use addresses)
	famProto := buf[13]
	fam := famProto >> 4
	proto := famProto & 0x0f
	if proto != 0x01 && proto != 0x02 { // STREAM or DGRAM; we care about STREAM only
		return Info{}, ErrNotProxy
	}
	addrLen := int(binary.BigEndian.Uint16(buf[14:16]))
	totalLen := 16 + addrLen
	if len(buf) < totalLen {
		return Info{}, ErrNeedMore
	}
	info := Info{Version: VersionV2, Length: totalLen}
	if cmd == 0x00 {
		return info, nil // LOCAL — no client info
	}
	var addrBytes []byte
	switch fam {
	case 0x1: // IPv4
		if addrLen < 12 {
			return Info{}, ErrNotProxy
		}
		addrBytes = buf[16 : 16+12]
		s, _ := netip.AddrFromSlice(addrBytes[0:4])
		d, _ := netip.AddrFromSlice(addrBytes[4:8])
		info.SrcIP, info.DstIP = s, d
		info.SrcPort = binary.BigEndian.Uint16(addrBytes[8:10])
		info.DstPort = binary.BigEndian.Uint16(addrBytes[10:12])
	case 0x2: // IPv6
		if addrLen < 36 {
			return Info{}, ErrNotProxy
		}
		addrBytes = buf[16 : 16+36]
		s, _ := netip.AddrFromSlice(addrBytes[0:16])
		d, _ := netip.AddrFromSlice(addrBytes[16:32])
		info.SrcIP, info.DstIP = s, d
		info.SrcPort = binary.BigEndian.Uint16(addrBytes[32:34])
		info.DstPort = binary.BigEndian.Uint16(addrBytes[34:36])
	default:
		return Info{}, fmt.Errorf("unsupported address family %d", fam)
	}
	return info, nil
}
