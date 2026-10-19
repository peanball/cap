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

// TestIPv4FragmentsMatchThroughReassembly splits one ClientHello across two
// IPv4 fragments. Without engine-side defragmentation the SNI never becomes
// visible and the stream is dropped. With defrag in place, the CH matches
// and the stream is kept.
func TestIPv4FragmentsMatchThroughReassembly(t *testing.T) {
	srcMAC, dstMAC := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}, []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}
	cli, srv := net.ParseIP("10.0.0.1"), net.ParseIP("93.184.216.34")
	cs, ds := uint16(51000), uint16(443)

	ch := testgenpcap.TLSCH("peanball.net")
	syn := testgenpcap.EthIPv4(cli, srv, cs, ds, 1000, 0, 0x02, nil)

	// Reassembleable TCP+CH payload (the second packet's data, without the
	// IPv4 header — ip4defrag consumes IPv4 packets only).
	unfragmented := testgenpcap.IPv4TCP(cli, srv, cs, ds, 1001, 1, 0x18, ch)[testgenpcap.IPv4HdrLen:]

	// Split into two fragments at 8 bytes into the TCP+CH chunk (offset is
	// in 8-byte units, so 8 bytes in = offset 1).
	var frames [][]byte
	frames = append(frames, syn)

	for i, chunk := range [][]byte{unfragmented[:8], unfragmented[8:]} {
		last := i == 1
		ip := make([]byte, testgenpcap.IPv4HdrLen)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], wireconv.MustUint16(testgenpcap.IPv4HdrLen+len(chunk)))
		binary.BigEndian.PutUint16(ip[4:6], 0x4242) // identification: same for both fragments
		frag := uint16(i)
		if !last {
			frag |= 1 << 13 // MF
		}
		binary.BigEndian.PutUint16(ip[6:8], frag)
		ip[8] = 64
		ip[9] = 6
		copy(ip[12:16], cli.To4())
		copy(ip[16:20], srv.To4())
		frames = append(frames, testgenpcap.Eth(srcMAC, dstMAC, 0x0800, append(ip, chunk...)))
	}

	sniM, err := match.NewSNI([]string{"peanball.net"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	eng, err := New(Config{Matcher: sniM}, pcap.NewWriterRaw(&out, pcap.LinkEthernet, 65535, false, pcap.FormatClassic))
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
		t.Errorf("StreamsKept = %d, want 1 (CH visible only after reassembly)", got)
	}
}
