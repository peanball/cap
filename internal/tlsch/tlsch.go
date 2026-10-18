// Package tlsch parses TLS ClientHello records from a reassembled byte
// stream and extracts the Server Name Indication (SNI) and the plaintext
// fields of an Encrypted Client Hello (ECH) extension.
// Only the first record of the stream is considered; subsequent records,
// handshakes other than ClientHello, and any non-TLS-looking prefix make
// the parser decline.
package tlsch

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	// ErrNeedMore signals the caller hasn't yet buffered enough bytes to
	// decide whether this stream is a TLS ClientHello or not.
	ErrNeedMore = errors.New("need more bytes")

	// ErrNotTLS signals the stream will not contain a parseable ClientHello.
	// Once returned, the caller should stop asking.
	ErrNotTLS = errors.New("not a TLS ClientHello")

	// ErrTooBig signals the declared CH length exceeds maxCHLen, so we
	// refuse to buffer further.
	ErrTooBig = errors.New("ClientHello exceeds maxCHLen")
)

// maxCHLen is the largest declared ClientHello body we'll buffer before
// parsing. Real CHs with ML-KEM key shares approach 8 KiB; 32 KiB gives
// generous headroom for future extensions while still bounding memory.
const maxCHLen = 32 << 10

// maxSNILen is RFC 6066's hostname cap: host_name is a DNS name, max 253 bytes.
const maxSNILen = 253

// Extension types of interest.
const (
	extServerName = 0      // RFC 6066
	extECH        = 0xfe0d // RFC 9849 §5 encrypted_client_hello
)

// Info is what Parse recovers from a ClientHello.
type Info struct {
	// SNI is the lowercased server_name host_name, or "" if the extension is
	// absent. When the client offers ECH this is the ClientHelloOuter's
	// name (ECHConfig.public_name), not the origin it is really reaching.
	SNI string

	// ECH is non-nil when the ClientHello carries a well-formed outer
	// encrypted_client_hello extension. Without the server's key this
	// cannot distinguish a real ECH offer from GREASE ECH (RFC 9849 §6.2.1),
	// which is shaped to be indistinguishable on the wire.
	ECH *ECH
}

// ECH holds the plaintext fields of an outer encrypted_client_hello
// extension (RFC 9849 §5). The encrypted ClientHelloInner is not decoded.
type ECH struct {
	KDF, AEAD  uint16 // HpkeSymmetricCipherSuite
	ConfigID   uint8
	EncLen     int // length of the HPKE encapsulated key
	PayloadLen int // length of the AEAD ciphertext (padded inner CH + tag)
}

// Parse returns the SNI and ECH info from the first TLS record of the
// stream in buf, or an error. buf must contain the client→server
// direction's bytes from the start.
//
// Recognized TLS versions: 0x0301..0x0304 as record-layer version. Version
// 0x0300 (SSLv3) and anything else yields ErrNotTLS. No cipher or extension
// validation beyond what's needed to locate server_name and
// encrypted_client_hello. A malformed encrypted_client_hello extension is
// ignored (Info.ECH stays nil); a malformed server_name is an error.
//
// On ErrNeedMore the caller should append more bytes and call again. On
// ErrNotTLS or ErrTooBig the stream will never match.
func Parse(buf []byte) (Info, error) {
	if len(buf) < 5 {
		return Info{}, ErrNeedMore
	}
	// Record header: type(1) version(2) length(2)
	if buf[0] != 22 { // handshake
		return Info{}, ErrNotTLS
	}
	ver := binary.BigEndian.Uint16(buf[1:3])
	if ver < 0x0301 || ver > 0x0304 {
		return Info{}, ErrNotTLS
	}
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	// The first record may carry multiple handshake messages, but a CH's own
	// framing tells us what we need; CH body length in the handshake header
	// is authoritative for us, and we must wait for it in full.
	if recLen > maxCHLen+4 { // +4 for handshake header
		return Info{}, ErrTooBig
	}
	if len(buf) < 5+recLen {
		return Info{}, ErrNeedMore
	}
	rec := buf[5 : 5+recLen]
	if len(rec) < 4 {
		return Info{}, ErrNotTLS
	}
	if rec[0] != 1 { // HandshakeType: client_hello
		return Info{}, ErrNotTLS
	}
	chLen := int(rec[1])<<16 | int(rec[2])<<8 | int(rec[3])
	if chLen > len(rec)-4 {
		// Legit but fragmented beyond first record; we don't reassemble
		// handshake records. Bail — caller treats as not-matchable.
		return Info{}, ErrNotTLS
	}
	ch := rec[4 : 4+chLen]
	return parseCH(ch)
}

func parseCH(ch []byte) (Info, error) {
	// ClientHello body: legacy_version(2) random(32) session_id_len(1)
	// session_id(0-32) cipher_suites_len(2) cipher_suites
	// compression_methods_len(1) compression_methods extensions_len(2)
	// extensions.
	if len(ch) < 34 {
		return Info{}, ErrNotTLS
	}
	p := 34 // skip version + random
	if len(ch) < p+1 {
		return Info{}, ErrNotTLS
	}
	sidLen := int(ch[p])
	p++
	if len(ch) < p+sidLen+2 {
		return Info{}, ErrNotTLS
	}
	p += sidLen
	csLen := int(binary.BigEndian.Uint16(ch[p : p+2]))
	p += 2
	if len(ch) < p+csLen+1 {
		return Info{}, ErrNotTLS
	}
	p += csLen
	cmLen := int(ch[p])
	p++
	if len(ch) < p+cmLen+2 {
		return Info{}, ErrNotTLS
	}
	p += cmLen
	extLen := int(binary.BigEndian.Uint16(ch[p : p+2]))
	p += 2
	if len(ch) < p+extLen {
		return Info{}, ErrNotTLS
	}
	exts := ch[p : p+extLen]
	var info Info
	sniSeen := false
	for len(exts) >= 4 {
		et := binary.BigEndian.Uint16(exts[0:2])
		el := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if len(exts) < el {
			if sniSeen {
				// SNI was already recovered; a truncated tail doesn't undo it.
				return info, nil
			}
			return Info{}, ErrNotTLS
		}
		body := exts[:el]
		exts = exts[el:]
		switch et {
		case extServerName:
			if sniSeen {
				continue // first one wins
			}
			name, err := parseServerName(body)
			if err != nil {
				return Info{}, err
			}
			info.SNI = name
			sniSeen = true
		case extECH:
			if info.ECH == nil {
				info.ECH = parseECH(body)
			}
		}
	}
	return info, nil // legal CH; SNI/ECH are zero if their extensions are absent
}

// parseECH decodes an ECHClientHello of type outer (RFC 9849 §5):
//
//	type(1)=0 kdf_id(2) aead_id(2) config_id(1) enc<0..2^16-1> payload<1..2^16-1>
//
// It returns nil for the inner type and for anything malformed, including
// trailing bytes: a ClientHello on the wire never carries type inner.
func parseECH(b []byte) *ECH {
	if len(b) < 8 || b[0] != 0 {
		return nil
	}
	e := &ECH{
		KDF:      binary.BigEndian.Uint16(b[1:3]),
		AEAD:     binary.BigEndian.Uint16(b[3:5]),
		ConfigID: b[5],
		EncLen:   int(binary.BigEndian.Uint16(b[6:8])),
	}
	b = b[8:]
	if len(b) < e.EncLen+2 {
		return nil
	}
	b = b[e.EncLen:]
	e.PayloadLen = int(binary.BigEndian.Uint16(b[0:2]))
	if e.PayloadLen == 0 || len(b)-2 != e.PayloadLen {
		return nil
	}
	return e
}

// parseServerName extracts the first DNS hostname from the ServerNameList.
// RFC 6066 §3: list is a 2-byte total length, then per-entry: type(1) len(2) data.
// type 0 = host_name. We only look at the first entry — subsequent entries,
// if any, are malformed by spec.
func parseServerName(b []byte) (string, error) {
	if len(b) < 2 {
		return "", ErrNotTLS
	}
	total := int(binary.BigEndian.Uint16(b[0:2]))
	b = b[2:]
	if len(b) < total {
		return "", ErrNotTLS
	}
	b = b[:total]
	if len(b) < 3 {
		return "", ErrNotTLS
	}
	if b[0] != 0 { // host_name type
		return "", nil // non-DNS name type — treat as no SNI
	}
	nameLen := int(binary.BigEndian.Uint16(b[1:3]))
	if nameLen > maxSNILen || len(b[3:]) < nameLen {
		return "", ErrNotTLS
	}
	name := b[3 : 3+nameLen]
	// Lowercase in place via fresh copy; avoid mutation of input buffer.
	out := make([]byte, nameLen)
	for i, c := range name {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	// Reject if it contains bytes outside printable DNS-ish set — protects
	// against early-terminate tricks and invalid UTF-8 in suffix matching.
	for _, c := range out {
		if c < 0x20 || c == 0x7f || c > 0x7e {
			return "", fmt.Errorf("invalid SNI byte 0x%02x", c)
		}
	}
	return string(out), nil
}
