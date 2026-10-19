package pcap

import (
	"bytes"
	"io"
	"testing"
	"time"
)

// buildPcap assembles a synthetic pcap stream in memory for tests.
func buildPcap(t *testing.T, nano bool, link LinkType, records []Record) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := NewWriterRaw(&buf, link, 65535, nano, FormatClassic)
	for _, r := range records {
		if err := w.Record(r); err != nil {
			t.Fatalf("write record: %v", err)
		}
	}
	if err := w.Err(); err != nil {
		t.Fatalf("writer err: %v", err)
	}
	return buf.Bytes()
}

func TestRoundTrip(t *testing.T) {
	base := time.Unix(1700000000, 0)
	in := []Record{
		{Timestamp: base.Add(123456 * time.Nanosecond), Data: []byte{0xde, 0xad, 0xbe, 0xef}},
		{Timestamp: base.Add(time.Second + time.Microsecond), Data: bytes.Repeat([]byte{0x41}, 1500)},
		{Timestamp: base.Add(2 * time.Second).Add(999999 * time.Microsecond), Data: nil},
	}
	raw := buildPcap(t, false, LinkEthernet, in)

	r, err := NewReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if r.nanoResolution() {
		t.Error("nano should be false for µs magic")
	}
	if r.Format() != FormatClassic {
		t.Errorf("Format = %v, want classic", r.Format())
	}
	if r.LinkType() != LinkEthernet {
		t.Errorf("LinkType = %v want %v", r.LinkType(), LinkEthernet)
	}
	var got []Record
	for i := 0; ; i++ {
		rec, err := r.Record()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		// Copy before append; Data aliases the reader buffer.
		cp := rec
		cp.Data = append([]byte(nil), rec.Data...)
		got = append(got, cp)
	}
	if len(got) != len(in) {
		t.Fatalf("got %d records, want %d", len(got), len(in))
	}
	// µs wire encoding truncates ns: check equality at µs precision.
	for i := range in {
		want := in[i].Timestamp.Truncate(time.Microsecond)
		if !got[i].Timestamp.Equal(want) {
			t.Errorf("record %d ts = %v want %v", i, got[i].Timestamp, want)
		}
		if !bytes.Equal(got[i].Data, in[i].Data) {
			t.Errorf("record %d data mismatch", i)
		}
	}
}

// TestEndianness exercises the big-endian global-header path. The packet
// records inside would also be big-endian; here we only check header fields.
func TestEndianness(t *testing.T) {
	var be bytes.Buffer
	binary32 := func(v uint32) []byte {
		return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
	}
	be.Write(binary32(0xa1b2c3d4)) // µs magic, BE on disk
	be.Write([]byte{0, 2, 0, 4})   // version 2.4
	be.Write(binary32(0))          // thiszone
	be.Write(binary32(0))          // sigfigs
	be.Write(binary32(65535))      // snaplen
	be.Write(binary32(1))          // linktype Ethernet
	r, err := NewReader(bytes.NewReader(be.Bytes()))
	if err != nil {
		t.Fatalf("NewReader BE: %v", err)
	}
	if r.LinkType() != LinkEthernet {
		t.Errorf("BE linktype = %v want %v", r.LinkType(), LinkEthernet)
	}
	if r.Snaplen() != 65535 {
		t.Errorf("BE snaplen = %d want 65535", r.Snaplen())
	}
}

func TestRejectsBadMagic(t *testing.T) {
	_, err := NewReader(bytes.NewReader([]byte{0x0a, 0x0d, 0x0d, 0x0a, 1, 2, 3, 4}))
	if err == nil {
		t.Fatal("expected error for pcapng magic")
	}
}

// TestTruncatedRecord: a pipe dying mid-record is not a parse error; the
// reader reports clean EOF so a buffered stream can flush.
func TestTruncatedRecord(t *testing.T) {
	raw := buildPcap(t, false, LinkEthernet, []Record{{Data: []byte{1, 2, 3}}})
	r, err := NewReader(bytes.NewReader(raw[:len(raw)-1]))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	if _, err := r.Record(); err != io.EOF {
		t.Errorf("want io.EOF on mid-record truncation, got %v", err)
	}
}
