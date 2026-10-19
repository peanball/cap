package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"slices"
	"testing"
	"time"

	"go.peanball.net/cap/internal/match"
	"go.peanball.net/cap/internal/pcap"
	"go.peanball.net/cap/internal/testgenpcap"
)

// stubMatcher matches any buffer that starts with the given prefix.
type stubMatcher struct{ prefix []byte }

func (m stubMatcher) Consider(buf []byte) match.Verdict {
	if len(buf) < len(m.prefix) {
		// Only report NeedMore if buf is a proper prefix of ours.
		for i, b := range buf {
			if b != m.prefix[i] {
				return match.NoMatch
			}
		}
		return match.NeedMore
	}
	for i, b := range m.prefix {
		if buf[i] != b {
			return match.NoMatch
		}
	}
	return match.Match
}

// buildTCPFrame builds a minimal Ethernet+IPv4+TCP frame. Thin alias over
// testgenpcap.Eth; the harness uses it constantly and the shared builder is
// the same shape.
func buildTCPFrame(srcMAC, dstMAC []byte, src, dst net.IP, sp, dp uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	return testgenpcap.Eth(srcMAC, dstMAC, 0x0800, testgenpcap.IPv4TCP(src, dst, sp, dp, seq, ack, flags, payload))
}

// harness drives packets of one TCP connection (client 10.0.0.1:51000 to
// 93.184.216.34:443) through an engine, at times relative to t0.
type harness struct {
	t   *testing.T
	eng *Engine
	t0  time.Time
}

func newHarness(t *testing.T, cfg Config) *harness {
	t.Helper()
	var out bytes.Buffer
	eng, err := New(cfg, pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &harness{t: t, eng: eng, t0: time.Now()}
}

// send injects one packet, from the client if fromCli, else from the server.
func (h *harness) send(fromCli bool, seq, ack uint32, flags uint8, payload []byte, at time.Duration) {
	h.t.Helper()
	cliMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srvMAC := []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	cli, srv := net.ParseIP("10.0.0.1"), net.ParseIP("93.184.216.34")
	var data []byte
	if fromCli {
		data = buildTCPFrame(cliMAC, srvMAC, cli, srv, 51000, 443, seq, ack, flags, payload)
	} else {
		data = buildTCPFrame(srvMAC, cliMAC, srv, cli, 443, 51000, seq, ack, flags, payload)
	}
	if err := h.eng.Process(pcap.LinkEthernet, h.t0.Add(at), data); err != nil {
		h.t.Fatalf("Process: %v", err)
	}
}

// open plays the handshake and the client's first payload (3 packets).
func (h *harness) open(request string) {
	h.t.Helper()
	h.send(true, 1000, 0, 0x02, nil, 0)
	h.send(false, 9000, 1001, 0x12, nil, time.Millisecond)
	h.send(true, 1001, 9001, 0x18, []byte(request), 2*time.Millisecond)
}

// tick advances engine time with a packet that isn't TCP.
func (h *harness) tick(at time.Duration) {
	h.t.Helper()
	if err := h.eng.Process(pcap.LinkEthernet, h.t0.Add(at), []byte{0}); err != nil {
		h.t.Fatalf("Process: %v", err)
	}
}

func (h *harness) out() uint64 { return h.eng.Stats().PacketsOut }

// TestClosedStreamLingers: a kept stream that closes keeps forwarding its
// late packets for the linger window, advises a flush when it closes and
// for each late packet, and is then evicted so Engine.streams doesn't leak.
func TestClosedStreamLingers(t *testing.T) {
	h := newHarness(t, Config{Matcher: stubMatcher{prefix: []byte("GET /")}, Linger: 100 * time.Millisecond})
	h.open("GET / HTTP/1.1\r\n")
	if got := h.out(); got != 3 {
		t.Fatalf("after match: %d packets out, want the 3 replayed", got)
	}
	if h.eng.FlushAdvised() {
		t.Error("flush advised while the connection is still open")
	}

	h.send(true, 1017, 9001, 0x11, nil, 3*time.Millisecond) // client FIN
	if len(h.eng.streams) != 1 || h.eng.FlushAdvised() {
		t.Errorf("after one FIN: streams=%d, want 1 and no flush advice", len(h.eng.streams))
	}
	h.send(false, 9001, 1018, 0x11, nil, 4*time.Millisecond) // server FIN: closed
	if len(h.eng.streams) != 1 {
		t.Errorf("after both FINs: streams=%d, want the closed stream still lingering", len(h.eng.streams))
	}
	if !h.eng.FlushAdvised() {
		t.Error("no flush advised when the connection closed")
	}

	h.send(true, 1018, 9002, 0x10, nil, 5*time.Millisecond) // final ACK
	if got := h.out(); got != 6 {
		t.Errorf("straggler: %d packets out, want 6", got)
	}
	if !h.eng.FlushAdvised() {
		t.Error("no flush advised for the straggler")
	}

	h.tick(200 * time.Millisecond)
	if len(h.eng.streams) != 0 {
		t.Errorf("after the linger window: streams=%d, want 0", len(h.eng.streams))
	}
	h.send(true, 1018, 9002, 0x10, nil, 201*time.Millisecond)
	if got := h.out(); got != 6 {
		t.Errorf("packet after the window was forwarded: %d out, want 6", got)
	}
}

// TestResetStreamLingers is the RST side of TestClosedStreamLingers: both
// ends commonly send one.
func TestResetStreamLingers(t *testing.T) {
	h := newHarness(t, Config{Matcher: stubMatcher{prefix: []byte("GET")}, Linger: 100 * time.Millisecond})
	h.open("GET x")
	h.eng.FlushAdvised()

	h.send(true, 1006, 9001, 0x14, nil, 3*time.Millisecond) // RST+ACK
	if len(h.eng.streams) != 1 || !h.eng.FlushAdvised() {
		t.Errorf("after RST: streams=%d, want 1 lingering and flush advised", len(h.eng.streams))
	}
	h.send(false, 9001, 0, 0x04, nil, 4*time.Millisecond) // peer's RST
	if got := h.out(); got != 5 {
		t.Errorf("peer RST: %d packets out, want 5", got)
	}
	h.tick(200 * time.Millisecond)
	if len(h.eng.streams) != 0 {
		t.Errorf("after the linger window: streams=%d, want 0", len(h.eng.streams))
	}
}

// TestPKTAPDecode: a packet arriving on Darwin's `-i any` wire wears a
// 156-byte PKTAP header whose DLT field says Ethernet and whose payload is
// the inner frame. The engine must decode through it and track the inner
// connection as one stream (proven indirectly by the kept counter on match).
func TestPKTAPDecode(t *testing.T) {
	cliMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	srvMAC := []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	cli, srv := net.ParseIP("10.0.0.1"), net.ParseIP("93.184.216.34")

	wrap := func(inner []byte) []byte {
		var hdr [156]byte
		binary.LittleEndian.PutUint32(hdr[0:4], 156)        // header length
		binary.LittleEndian.PutUint32(hdr[4:8], 1)          // PKT_REC_PACKET
		binary.LittleEndian.PutUint32(hdr[8:12], 1)         // DLT_EN10MB = 1
		copy(hdr[0x0C:0x0C+24], []byte("en0\x00"))          // interface name
		binary.LittleEndian.PutUint32(hdr[0x28:0x2C], 2)    // AF_INET
		binary.LittleEndian.PutUint32(hdr[0x2C:0x30], 14)   // link-layer hdr
		binary.LittleEndian.PutUint32(hdr[0x34:0x38], 4242) // PID
		copy(hdr[0x38:0x38+20], []byte("curl\x00"))         // command name
		return append(hdr[:], inner...)
	}

	var out bytes.Buffer
	eng, err := New(Config{Matcher: stubMatcher{prefix: []byte("GET ")}}, pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t0 := time.Unix(1700000000, 0)
	ms := func(i int) time.Time { return t0.Add(time.Duration(i) * time.Millisecond) }

	frames := [][]byte{
		wrap(buildTCPFrame(cliMAC, srvMAC, cli, srv, 51000, 443, 1000, 0, 0x02, nil)),
		wrap(buildTCPFrame(srvMAC, cliMAC, srv, cli, 443, 51000, 9000, 1001, 0x12, nil)),
		wrap(buildTCPFrame(cliMAC, srvMAC, cli, srv, 51000, 443, 1001, 9001, 0x18, []byte("GET / HTTP/1.0\r\n"))),
	}
	for i, f := range frames {
		if err := eng.Process(pcap.LinkApplePKTAP, ms(i), f); err != nil {
			t.Fatalf("Process PKTAP %d: %v", i, err)
		}
	}
	if got := eng.Stats().StreamsKept; got != 1 {
		t.Errorf("StreamsKept = %d, want 1 (PKTAP-wrapped client GET matched)", got)
	}
	if got := eng.Stats().PacketsIn; got != 3 {
		t.Errorf("PacketsIn = %d, want 3", got)
	}
}

// TestReusedTupleIsNotAStraggler: a SYN on the 4-tuple of a lingering stream
// starts a new connection, so its packets must not be forwarded as late
// packets of the old one.
func TestReusedTupleIsNotAStraggler(t *testing.T) {
	h := newHarness(t, Config{Matcher: stubMatcher{prefix: []byte("GET")}, Linger: time.Minute})
	h.open("GET x")
	h.send(true, 1006, 9001, 0x14, nil, 3*time.Millisecond) // RST+ACK
	before := h.out()

	h.send(true, 5000, 0, 0x02, nil, 10*time.Millisecond)
	h.send(false, 9500, 5001, 0x12, nil, 11*time.Millisecond)
	h.send(true, 5001, 9501, 0x18, []byte("NOPE"), 12*time.Millisecond)
	if got := h.out(); got != before {
		t.Errorf("reused tuple leaked %d packets into the output", got-before)
	}
}

// TestUnkeptStreamCloseAdvisesNothing: only kept connections justify a
// flush, or every dropped connection would defeat output batching.
func TestUnkeptStreamCloseAdvisesNothing(t *testing.T) {
	h := newHarness(t, Config{Matcher: stubMatcher{prefix: []byte("GET")}})
	h.open("NOPE")
	h.send(true, 1005, 9001, 0x11, nil, 3*time.Millisecond)
	h.send(false, 9001, 1006, 0x11, nil, 4*time.Millisecond)
	h.send(true, 1006, 9002, 0x10, nil, 5*time.Millisecond)
	if h.eng.FlushAdvised() {
		t.Error("flush advised for a dropped connection")
	}
	if got := h.out(); got != 0 {
		t.Errorf("%d packets of a dropped connection were output", got)
	}
}

// buildCH is a ClientHello record with an SNI extension and, if ech, an
// outer encrypted_client_hello extension. Aliased from testgenpcap.
func buildCH(sni string, ech bool) []byte { return testgenpcap.CH(sni, ech) }

// feedCH plays a handshake plus one ClientHello for a fresh connection.
func feedCH(t *testing.T, eng *Engine, t0 time.Time, port uint16, ch []byte) {
	t.Helper()
	srcMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	dstMAC := []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	cli, srv := net.ParseIP("10.0.0.1"), net.ParseIP("93.184.216.34")
	for i, f := range [][]byte{
		buildTCPFrame(srcMAC, dstMAC, cli, srv, port, 443, 1000, 0, 0x02, nil),
		buildTCPFrame(dstMAC, srcMAC, srv, cli, 443, port, 9000, 1001, 0x12, nil),
		buildTCPFrame(srcMAC, dstMAC, cli, srv, port, 443, 1001, 9001, 0x18, ch),
	} {
		if err := eng.Process(pcap.LinkEthernet, t0.Add(time.Duration(i)*time.Millisecond), f); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
}

// TestDroppedECHCounted: a dropped stream is counted as ECH only when its
// ClientHello offered the extension, itemized by outer SNI, and a kept
// stream (here: matched on the outer SNI) is not counted.
func TestDroppedECHCounted(t *testing.T) {
	m, err := match.NewSNI([]string{"wanted.example"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng, err := New(Config{Matcher: m}, pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	feedCH(t, eng, t0, 50001, buildCH("public.example", true))
	feedCH(t, eng, t0, 50002, buildCH("public.example", true))
	feedCH(t, eng, t0, 50003, buildCH("other-public.example", true))
	feedCH(t, eng, t0, 50004, buildCH("plain.example", false))
	feedCH(t, eng, t0, 50005, buildCH("wanted.example", true))

	s := eng.Stats()
	if s.StreamsKept != 1 || s.StreamsDrop != 4 {
		t.Errorf("kept=%d dropped=%d, want 1 and 4", s.StreamsKept, s.StreamsDrop)
	}
	if s.ECHDropped != 3 {
		t.Errorf("ECHDropped = %d, want 3", s.ECHDropped)
	}
	want := []ECHName{{"public.example", 2}, {"other-public.example", 1}}
	if got := eng.ECHNames(); !slices.Equal(got, want) {
		t.Errorf("ECHNames = %v, want %v", got, want)
	}
}

// TestECHNamesBounded: past maxECHNames distinct outer SNIs the table stops
// growing, but the total and the already-tracked names keep counting.
func TestECHNamesBounded(t *testing.T) {
	m, err := match.NewSNI([]string{"wanted.example"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng, err := New(Config{Matcher: m}, pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	const extra = 5
	port := uint16(10000)
	for i := 0; i < maxECHNames+extra; i++ {
		feedCH(t, eng, t0, port, buildCH(fmt.Sprintf("n%d.example", i), true))
		port++
	}
	feedCH(t, eng, t0, port, buildCH("n0.example", true)) // tracked name still counts

	if got := eng.Stats().ECHDropped; got != maxECHNames+extra+1 {
		t.Errorf("ECHDropped = %d, want %d", got, maxECHNames+extra+1)
	}
	names := eng.ECHNames()
	if len(names) != maxECHNames {
		t.Errorf("itemized %d names, want %d", len(names), maxECHNames)
	}
	if names[0] != (ECHName{"n0.example", 2}) {
		t.Errorf("top = %v, want n0.example x2", names[0])
	}
}
