package testgenpcap

import (
	"bytes"
	"fmt"
	"time"

	"go.peanball.net/cap/internal/pcap"
)

// Fixture is one named scenario. Data is the full classic-pcap byte stream;
// Name doubles as the file name under testdata/.
type Fixture struct {
	Name string
	Data []byte
}

// ManifestName is the per-directory sha256 manifest next to each fixture
// set; both test/main.go and the drift test reference it.
const ManifestName = "fixtures.sha256"

// cmdCapFixtures feed tests under cmd/cap; engineFixtures feed
// internal/engine. The drift test regenerates both maps and the replayer
// reads the resulting files, so the generator is the single source of truth.
var cmdCapFixtures = map[string]func() []pcap.Record{
	"sni_fragmented.pcap":  sniFragmented,
	"tunnel_sni.pcap":      tunnelSNI,
	"tunnel_ip_gate.pcap":  tunnelIPGate,
	"sni_two_streams.pcap": sniTwoStreams,
}

var engineFixtures = map[string]func() []pcap.Record{
	"unpack_4in6.pcap":          unpack4in6,
	"unpack_6in6.pcap":          unpack6in6,
	"unpack_proxy_rewrite.pcap": unpackProxyRewrite,
}

// Dirs maps each fixture directory to the fixtures that live in it. The CLI
// (test/main.go) and the drift test both drive off this; it is the only
// inventory a new fixture or a new directory has to touch.
func Dirs() map[string][]string {
	return map[string][]string{
		"cmd/cap/testdata": {
			"sni_fragmented.pcap", "tunnel_sni.pcap", "tunnel_ip_gate.pcap", "sni_two_streams.pcap",
		},
		"internal/engine/testdata": {
			"unpack_4in6.pcap", "unpack_6in6.pcap", "unpack_proxy_rewrite.pcap",
		},
	}
}

// Generate returns the fixture bytes for name, or an error if unknown.
func Generate(dir, name string) ([]byte, error) {
	m := cmdCapFixtures
	if dir == "internal/engine/testdata" {
		m = engineFixtures
	}
	gen, ok := m[name]
	if !ok {
		return nil, fmt.Errorf("unknown fixture %s/%s", dir, name)
	}
	return Marshal(gen())
}

// Marshal turns records into a classic-pcap byte stream with the same
// parameters the tests use (Ethernet, snap 65535, µs timestamps).
func Marshal(records []pcap.Record) ([]byte, error) {
	var buf bytes.Buffer
	wr := pcap.NewWriterRaw(&buf, pcap.LinkEthernet, 65535, false)
	for _, r := range records {
		if err := wr.Record(r); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// ReadAll replays b through pcap.Reader and returns copies of every record.
// The copies matter: Reader.Record aliases an internal buffer, and the drift
// test and fixture-replaying tests compare the records after the file is
// closed.
func ReadAll(b []byte) ([]pcap.Record, error) {
	r, err := pcap.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	var out []pcap.Record
	for {
		r, err := r.Record()
		if err != nil {
			return out, nil
		}
		cp := r
		cp.Data = append([]byte(nil), r.Data...)
		out = append(out, cp)
	}
}

// Record constructor.

func rec(data []byte, at time.Time) pcap.Record {
	return pcap.Record{
		Timestamp: at,
		Data:      data,
	}
}

// sniFragmented is TestSNIFragmentedCH: one connection whose ClientHello is
// split across two segments 20 bytes in.
func sniFragmented() []pcap.Record {
	cli, srv := ips("10.0.0.1"), ips("93.184.216.34")
	cs, ds := uint16(50001), uint16(443)
	ch := TLSCH("peanball.net")
	splitAt := 20
	return []pcap.Record{
		rec(EthIPv4(cli, srv, cs, ds, 1000, 0, 0x02, nil), ms(0)),
		rec(EthIPv4(srv, cli, ds, cs, 9000, 1001, 0x12, nil), ms(1)),
		rec(EthIPv4(cli, srv, cs, ds, 1001, 9001, 0x10, nil), ms(2)),
		rec(EthIPv4(cli, srv, cs, ds, 1001, 9001, 0x18, ch[:splitAt]), ms(3)),
		rec(EthIPv4(cli, srv, cs, ds, 1001+uint32(splitAt), 9001, 0x18, ch[splitAt:]), ms(4)),
		rec(EthIPv4(srv, cli, ds, cs, 9001, 1001+uint32(len(ch)), 0x18, make([]byte, 50)), ms(5)),
		rec(EthIPv4(cli, srv, cs, ds, 1001+uint32(len(ch)), 9051, 0x11, nil), ms(6)),
	}
}

// tunnelSNI is TestTunneledSNIMatch: one 4-in-6 connection carrying the CH
// for target.example.com.
func tunnelSNI() []pcap.Record {
	src6, dst6 := ips("2001:db8::1"), ips("2001:db8::2")
	src4, dst4 := ips("10.0.0.1"), ips("10.0.0.2")
	sp, dp := uint16(51000), uint16(443)
	return []pcap.Record{
		rec(Eth6in4(src6, dst6, src4, dst4, sp, dp, 1000, 1, 0x02, nil), ms(0)),
		rec(Eth6in4(src6, dst6, src4, dst4, sp, dp, 1001, 1, 0x18, TLSCH("target.example.com")), ms(1)),
		rec(Eth6in4(src6, dst6, src4, dst4, sp, dp, 2000, 1, 0x18, []byte("app")), ms(2)),
		rec(Eth6in4(src6, dst6, src4, dst4, sp, dp, 2100, 1, 0x11, nil), ms(3)),
	}
}

// tunnelIPGate is TestTunnelIPGate: two 4-in-6 streams with identical inner
// SNI, but only one's outer endpoints match the --tunnel-ip CIDR.
func tunnelIPGate() []pcap.Record {
	src4, dst4 := ips("10.0.0.1"), ips("10.0.0.2")
	allowS, allowD := ips("2001:db8::1"), ips("2001:db8::2")
	denyS, denyD := ips("2001:db8:dead::1"), ips("2001:db8:dead::2")
	return []pcap.Record{
		// allowed outer
		rec(Eth6in4(allowS, allowD, src4, dst4, 51000, 443, 1000, 1, 0x02, nil), ms(0)),
		rec(Eth6in4(allowS, allowD, src4, dst4, 51000, 443, 1001, 1, 0x18, TLSCH("target.example.com")), ms(1)),
		rec(Eth6in4(allowS, allowD, src4, dst4, 51000, 443, 2000, 1, 0x18, []byte("app")), ms(2)),
		// denied outer; SNI would match but the gate drops it at ConsiderKey
		rec(Eth6in4(denyS, denyD, src4, dst4, 52000, 443, 5000, 1, 0x02, nil), ms(0)),
		rec(Eth6in4(denyS, denyD, src4, dst4, 52000, 443, 5001, 1, 0x18, TLSCH("target.example.com")), ms(1)),
		rec(Eth6in4(denyS, denyD, src4, dst4, 52000, 443, 6000, 1, 0x18, []byte("app")), ms(2)),
	}
}

// sniTwoStreams is TestSNIOnlyMatchedStreamKeptInOutput: two parallel
// connections with different clients and SNIs; only one's name matches.
func sniTwoStreams() []pcap.Record {
	srv := ips("93.184.216.34")
	a, b := ips("10.0.0.1"), ips("10.0.0.2")
	return []pcap.Record{
		rec(EthIPv4(a, srv, 50001, 443, 1000, 1, 0x02, nil), ms(0)),
		rec(EthIPv4(a, srv, 50001, 443, 1001, 1, 0x18, TLSCH("target.example.com")), ms(1)),
		rec(EthIPv4(a, srv, 50001, 443, 2000, 1, 0x18, []byte("app data A")), ms(2)),
		rec(EthIPv4(a, srv, 50001, 443, 2100, 1, 0x11, nil), ms(3)),
		rec(EthIPv4(b, srv, 50002, 443, 5000, 1, 0x02, nil), ms(1)),
		rec(EthIPv4(b, srv, 50002, 443, 5001, 1, 0x18, TLSCH("other.example.org")), ms(2)),
		rec(EthIPv4(b, srv, 50002, 443, 6000, 1, 0x18, []byte("app data B")), ms(3)),
		rec(EthIPv4(b, srv, 50002, 443, 6100, 1, 0x11, nil), ms(4)),
	}
}

// unpack4in6/unpack6in6 are TestTunnelUnpackDuplicates and its 6-in-6 twin:
// handshake + CH for inner.example + one server response.
func unpack4in6() []pcap.Record {
	cli6, srv6 := ips("2001:db8::a"), ips("2001:db8::b")
	cli4, srv4 := ips("10.0.0.1"), ips("10.0.0.2")
	ch := TLSCH("inner.example")
	return []pcap.Record{
		rec(Eth6in4(cli6, srv6, cli4, srv4, 51000, 443, 1000, 0, 0x02, nil), ms(0)),
		rec(Eth6in4(srv6, cli6, srv4, cli4, 443, 51000, 9000, 1001, 0x12, nil), ms(1)),
		rec(Eth6in4(cli6, srv6, cli4, srv4, 51000, 443, 1001, 9001, 0x18, ch), ms(2)),
		rec(Eth6in4(srv6, cli6, srv4, cli4, 443, 51000, 9001, 1001+uint32(len(ch)), 0x18, []byte("resp")), ms(3)),
	}
}

func unpack6in6() []pcap.Record {
	cli6o, srv6o := ips("2001:db8::a"), ips("2001:db8::b")
	cli6i, srv6i := ips("fd00::1"), ips("fd00::2")
	ch := TLSCH("inner.example")
	return []pcap.Record{
		rec(Eth6in6(cli6o, srv6o, cli6i, srv6i, 51000, 443, 1000, 0, 0x02, nil), ms(0)),
		rec(Eth6in6(srv6o, cli6o, srv6i, cli6i, 443, 51000, 9000, 1001, 0x12, nil), ms(1)),
		rec(Eth6in6(cli6o, srv6o, cli6i, srv6i, 51000, 443, 1001, 9001, 0x18, ch), ms(2)),
		rec(Eth6in6(srv6o, cli6o, srv6i, cli6i, 443, 51000, 9001, 1001+uint32(len(ch)), 0x18, []byte("resp")), ms(3)),
	}
}

// unpackProxyRewrite is TestProxyUnpackRewritesTuple: a kept connection whose
// client opens with a PROXY v1 line, then keeps talking.
func unpackProxyRewrite() []pcap.Record {
	proxy := ips("10.0.0.9") // frontend
	mine := ips("192.0.2.1") // backend/origin
	hdr := []byte("PROXY TCP4 203.0.113.7 192.0.2.1 41234 443\r\nGET /")
	return []pcap.Record{
		rec(EthIPv4(mine, proxy, 50000, 443, 1000, 0, 0x02, nil), ms(0)),
		rec(EthIPv4(proxy, mine, 443, 50000, 9000, 1001, 0x12, nil), ms(1)),
		rec(EthIPv4(mine, proxy, 50000, 443, 1001, 9001, 0x18, hdr), ms(2)),
		rec(EthIPv4(proxy, mine, 443, 50000, 9001, 1001+uint32(len(hdr)), 0x18, []byte("HTTP/1.1 200")), ms(3)),
		rec(EthIPv4(mine, proxy, 50000, 443, 1001+uint32(len(hdr)), 9013, 0x18, []byte("more")), ms(4)),
	}
}
