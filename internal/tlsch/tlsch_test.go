package tlsch

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"net"
	"testing"

	"go.peanball.net/cap/internal/wireconv"
)

// ext frames one TLS extension.
func ext(typ uint16, body []byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, typ)
	b = binary.BigEndian.AppendUint16(b, wireconv.MustUint16(len(body)))
	return append(b, body...)
}

// sniExt is a server_name extension carrying name.
func sniExt(name string) []byte {
	entry := append([]byte{0}, binary.BigEndian.AppendUint16(nil, wireconv.MustUint16(len(name)))...)
	entry = append(entry, name...)
	list := binary.BigEndian.AppendUint16(nil, wireconv.MustUint16(len(entry)))
	return ext(extServerName, append(list, entry...))
}

// echBody encodes an ECHClientHello of type outer (RFC 9849 §5).
func echBody(kdf, aead uint16, configID uint8, enc, payload []byte) []byte {
	b := []byte{0}
	b = binary.BigEndian.AppendUint16(b, kdf)
	b = binary.BigEndian.AppendUint16(b, aead)
	b = append(b, configID)
	b = binary.BigEndian.AppendUint16(b, wireconv.MustUint16(len(enc)))
	b = append(b, enc...)
	b = binary.BigEndian.AppendUint16(b, wireconv.MustUint16(len(payload)))
	return append(b, payload...)
}

// buildCHExts constructs a minimal but structurally valid ClientHello
// carrying the given pre-framed extensions in order, wrapped in a TLS record.
func buildCHExts(t *testing.T, exts ...[]byte) []byte {
	t.Helper()
	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03}) // legacy_version TLS 1.2
	body.Write(make([]byte, 32))   // random
	body.WriteByte(0)              // session_id len
	binary.Write(&body, binary.BigEndian, uint16(2))
	body.Write([]byte{0x13, 0x01}) // TLS_AES_128_GCM_SHA256
	body.WriteByte(1)              // compression methods len
	body.WriteByte(0)              // null compression

	all := bytes.Join(exts, nil)
	binary.Write(&body, binary.BigEndian, wireconv.MustUint16(len(all)))
	body.Write(all)

	chBody := body.Bytes()
	var hs bytes.Buffer
	hs.WriteByte(1) // client_hello
	if len(chBody) > 0xffffff {
		t.Fatalf("CH body overflows 24-bit handshake length")
	}
	hs.Write([]byte{wireconv.MustUint8(len(chBody) >> 16), wireconv.MustUint8((len(chBody) >> 8) & 0xff), wireconv.MustUint8(len(chBody) & 0xff)})
	hs.Write(chBody)

	var rec bytes.Buffer
	rec.WriteByte(22) // handshake
	rec.Write([]byte{0x03, 0x01})
	binary.Write(&rec, binary.BigEndian, wireconv.MustUint16(hs.Len()))
	rec.Write(hs.Bytes())
	return rec.Bytes()
}

// buildCH is a ClientHello with only an SNI extension carrying name.
func buildCH(t *testing.T, name string) []byte {
	t.Helper()
	return buildCHExts(t, sniExt(name))
}

func TestSNI(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"example.com", "example.com"},
		{"api.example.com", "api.example.com"},
		{"UPPER.example.COM", "upper.example.com"}, // lowercased
		{"xn--nxasmq6b.example", "xn--nxasmq6b.example"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := Parse(buildCH(t, tc.name))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if info.SNI != tc.want {
				t.Errorf("SNI = %q want %q", info.SNI, tc.want)
			}
			if info.ECH != nil {
				t.Errorf("ECH = %+v, want nil", info.ECH)
			}
		})
	}
}

func TestFragmentedCH(t *testing.T) {
	full := buildCH(t, "split.example.com")
	// Feed byte-by-byte: must return ErrNeedMore until enough buffered, then
	// succeed with the same result.
	for i := 1; i < len(full); i++ {
		info, err := Parse(full[:i])
		if errors.Is(err, ErrTooBig) || errors.Is(err, ErrNotTLS) {
			t.Fatalf("prefix %d: unexpected err %v", i, err)
		}
		if err == nil {
			// success is only expected on the last (full) call
			if i != len(full) {
				t.Fatalf("prefix %d unexpectedly succeeded: %q", i, info.SNI)
			}
		}
	}
	info, err := Parse(full)
	if err != nil {
		t.Fatalf("full CH: %v", err)
	}
	if info.SNI != "split.example.com" {
		t.Errorf("got %q", info.SNI)
	}
}

func TestNotTLS(t *testing.T) {
	cases := [][]byte{
		{0x16, 0x03, 0x00, 0x00, 0x10},               // SSL 3.0
		{0x00, 0x03, 0x03, 0x00, 0x10},               // not handshake type
		[]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n"), // PROXY v1
		[]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
	}
	for i, c := range cases {
		if _, err := Parse(c); !errors.Is(err, ErrNotTLS) && !errors.Is(err, ErrNeedMore) {
			t.Errorf("case %d: want ErrNotTLS or ErrNeedMore, got %v", i, err)
		}
	}
}

func TestTooBigCH(t *testing.T) {
	// Record header claiming a huge CH.
	rec := []byte{22, 0x03, 0x03, 0xff, 0xff}
	if _, err := Parse(rec); !errors.Is(err, ErrTooBig) {
		t.Errorf("want ErrTooBig, got %v", err)
	}
}

// TestTruncatedTailKeepsSNI: once server_name has been read, a malformed
// extension after it must not turn the stream into a non-match.
func TestTruncatedTailKeepsSNI(t *testing.T) {
	bad := ext(0x1234, []byte{1, 2, 3, 4})
	bad = bad[:len(bad)-2] // header claims 4 bytes, only 2 follow
	info, err := Parse(buildCHExts(t, sniExt("kept.example.com"), bad))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SNI != "kept.example.com" {
		t.Errorf("SNI = %q", info.SNI)
	}
}

func TestECH(t *testing.T) {
	enc := make([]byte, 32)
	payload := make([]byte, 208)
	good := ext(extECH, echBody(0x0001, 0x0001, 0x7b, enc, payload))
	want := ECH{KDF: 1, AEAD: 1, ConfigID: 0x7b, EncLen: 32, PayloadLen: 208}

	// Each malformed case is an outer-type body with one defect.
	mut := func(f func(b []byte) []byte) []byte {
		return ext(extECH, f(echBody(1, 1, 0x7b, enc, payload)))
	}
	cases := []struct {
		name    string
		exts    [][]byte
		wantSNI string
		want    *ECH
	}{
		{"ECH after SNI", [][]byte{sniExt("public.example"), good}, "public.example", &want},
		{"ECH before SNI", [][]byte{good, sniExt("public.example")}, "public.example", &want},
		{"ECH without SNI", [][]byte{good}, "", &want},
		{"no ECH", [][]byte{sniExt("plain.example")}, "plain.example", nil},
		{"inner type", [][]byte{sniExt("plain.example"), ext(extECH, []byte{1})}, "plain.example", nil},
		{"payload longer than body", [][]byte{sniExt("plain.example"),
			mut(func(b []byte) []byte { return b[:len(b)-1] })}, "plain.example", nil},
		{"trailing bytes", [][]byte{sniExt("plain.example"),
			mut(func(b []byte) []byte { return append(b, 0) })}, "plain.example", nil},
		{"empty payload", [][]byte{sniExt("plain.example"),
			ext(extECH, echBody(1, 1, 0x7b, enc, nil))}, "plain.example", nil},
		{"enc overruns body", [][]byte{sniExt("plain.example"),
			ext(extECH, []byte{0, 0, 1, 0, 1, 0x7b, 0xff, 0xff, 1})}, "plain.example", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			info, err := Parse(buildCHExts(t, tc.exts...))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if info.SNI != tc.wantSNI {
				t.Errorf("SNI = %q want %q", info.SNI, tc.wantSNI)
			}
			switch {
			case tc.want == nil && info.ECH != nil:
				t.Errorf("ECH = %+v, want nil", *info.ECH)
			case tc.want != nil && info.ECH == nil:
				t.Errorf("ECH = nil, want %+v", *tc.want)
			case tc.want != nil && *info.ECH != *tc.want:
				t.Errorf("ECH = %+v, want %+v", *info.ECH, *tc.want)
			}
		})
	}
}

// TestGoClientECH parses the ClientHello written by crypto/tls's ECH
// client, an implementation independent of this package's reading of
// RFC 9849: the outer SNI must be the ECHConfig's public_name, the true
// name must not appear anywhere in the bytes, and the payload must be
// padded to a multiple of 32 plus the 16-byte AEAD tag (§6.1.3).
func TestGoClientECH(t *testing.T) {
	const public, secret = "public.example", "secret.example.org"

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := key.PublicKey().Bytes()

	// ECHConfigList with a single ECHConfig (RFC 9849 §4).
	var contents []byte
	contents = append(contents, 0x2a)                          // config_id
	contents = binary.BigEndian.AppendUint16(contents, 0x0020) // DHKEM(X25519, HKDF-SHA256)
	contents = binary.BigEndian.AppendUint16(contents, wireconv.MustUint16(len(pub)))
	contents = append(contents, pub...)
	contents = binary.BigEndian.AppendUint16(contents, 4)      // cipher_suites length
	contents = binary.BigEndian.AppendUint16(contents, 0x0001) // HKDF-SHA256
	contents = binary.BigEndian.AppendUint16(contents, 0x0001) // AES-128-GCM
	contents = append(contents, 32)                            // maximum_name_length
	contents = append(contents, wireconv.MustUint8(len(public)))
	contents = append(contents, public...)
	contents = binary.BigEndian.AppendUint16(contents, 0) // extensions
	cfg := binary.BigEndian.AppendUint16(nil, extECH)     // version
	cfg = binary.BigEndian.AppendUint16(cfg, wireconv.MustUint16(len(contents)))
	cfg = append(cfg, contents...)
	list := binary.BigEndian.AppendUint16(nil, wireconv.MustUint16(len(cfg)))
	list = append(list, cfg...)

	// Capture the client's first flight; the handshake then fails when the
	// "server" hangs up, which is fine.
	cli, srv := net.Pipe()
	first := make(chan []byte, 1)
	go func() {
		b := make([]byte, 1<<16)
		n, _ := srv.Read(b)
		srv.Close()
		first <- b[:n]
	}()
	c := tls.Client(cli, &tls.Config{
		ServerName:                     secret,
		MinVersion:                     tls.VersionTLS13,
		EncryptedClientHelloConfigList: list,
	})
	_ = c.Handshake()
	cli.Close()
	hello := <-first

	if bytes.Contains(hello, []byte(secret)) {
		t.Fatal("true server name is visible in the ClientHello")
	}
	info, err := Parse(hello)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if info.SNI != public {
		t.Errorf("SNI = %q, want public_name %q", info.SNI, public)
	}
	e := info.ECH
	if e == nil {
		t.Fatal("ECH not detected")
	}
	if e.ConfigID != 0x2a || e.KDF != 1 || e.AEAD != 1 || e.EncLen != 32 {
		t.Errorf("ECH = %+v, want config_id 0x2a kdf 1 aead 1 enc 32", *e)
	}
	if e.PayloadLen%32 != 16 {
		t.Errorf("PayloadLen = %d, want multiple of 32 plus 16", e.PayloadLen)
	}
}
