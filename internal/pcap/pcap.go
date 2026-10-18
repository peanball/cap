// Package pcap reads and writes classic libpcap capture files (not pcapng)
// as a thin adapter over github.com/gopacket/gopacket/pcapgo — the actively
// maintained gopacket fork. gopacket does the format work (four magic
// patterns, both endians, µs and ns); this package exists to give cap's
// engine a small surface that speaks Go primitives: Record carries a
// time.Time, the writer has a sticky error and flushes its header immediately
// so a downstream reader (tshark piping us) sees a valid stream before any
// packet matches, and the reader treats a mid-record truncation as clean EOF
// so piped streams end cleanly.
package pcap

import (
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// LinkType is gopacket's layers.LinkType. Since v1.7.4 it is uint16, so SLL2
// (276) and any future classic-pcap DLT values survive.
type LinkType = layers.LinkType

const (
	LinkEthernet  = layers.LinkTypeEthernet
	LinkRaw       = layers.LinkTypeRaw // DLT_RAW, raw IPv4/IPv6
	LinkLinuxSLL  = layers.LinkTypeLinuxSLL
	LinkIPv4      = layers.LinkTypeIPv4
	LinkIPv6      = layers.LinkTypeIPv6
	LinkLinuxSLL2 = layers.LinkTypeLinuxSLL2
)

// Record is a single captured packet. Data is the on-wire frame; OrigLen is
// the length the capture device saw. When produced by Reader.Record, Data
// aliases an internal buffer and must be copied if kept past the next Record
// call.
type Record struct {
	Timestamp time.Time
	Data      []byte
	// OrigLen is the captured frame's wire length. 0 means "as captured" —
	// callers only set it when the device truncated the frame.
	OrigLen int
}

// Reader iterates records from a classic pcap stream.
type Reader struct {
	rd  *pcapgo.Reader
	err error
}

// NewReader reads and validates the global header. Returns io errors directly.
func NewReader(r io.Reader) (*Reader, error) {
	g, err := pcapgo.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("read global header: %w", err)
	}
	return &Reader{rd: g}, nil
}

// LinkType returns the global-header link type.
func (r *Reader) LinkType() LinkType { return r.rd.LinkType() }

// Snaplen returns the global-header snap length.
func (r *Reader) Snaplen() uint32 { return r.rd.Snaplen() }

// nanoResolution reports whether the reader's global header promised ns, so
// a pass-through writer can mirror it. Fork's Resolution() works since v1.7.4
// (v1.1.19 had the return values inverted).
func (r *Reader) nanoResolution() bool {
	return r.rd.Resolution() == gopacket.TimestampResolutionNanosecond
}

// Record reads one packet record. io.EOF at clean end. On error, subsequent
// calls keep returning the same error. A mid-record truncation (a pipe killed
// mid-write) is reported as a clean io.EOF.
func (r *Reader) Record() (Record, error) {
	if r.err != nil {
		return Record{}, r.err
	}
	data, ci, err := r.rd.ZeroCopyReadPacketData()
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			// Mid-record truncation is how piped streams end; treat as EOF so
			// a downstream flush-advised stream isn't wedged.
			r.err = io.EOF
			return Record{}, io.EOF
		}
		r.err = err
		return Record{}, err
	}
	return Record{
		Timestamp: ci.Timestamp,
		Data:      data,
		OrigLen:   ci.Length,
	}, nil
}

// Writer emits a classic pcap stream. Not safe for concurrent use.
type Writer struct {
	w   io.Writer
	err error
	gw  *pcapgo.Writer
}

// NewWriter emits a global header mirroring rd (same link type, snaplen, and
// timestamp resolution) so pass-through output stays self-describing.
func NewWriter(w io.Writer, rd *Reader) *Writer {
	return NewWriterRaw(w, rd.LinkType(), rd.Snaplen(), rd.nanoResolution())
}

// NewWriterRaw emits a global header with explicit parameters. nano=true
// selects the ns-resolution wire magic; µs otherwise.
func NewWriterRaw(w io.Writer, link LinkType, snap uint32, nano bool) *Writer {
	wr := &Writer{w: w}
	if nano {
		wr.gw = pcapgo.NewWriterNanos(w)
	} else {
		wr.gw = pcapgo.NewWriter(w)
	}
	if err := wr.gw.WriteFileHeader(snap, link); err != nil {
		wr.err = err
		return wr
	}
	// Flush immediately, not just on WritePacket, so a downstream that opens
	// the stream sees a valid pcap before any packet matches — not after the
	// first buffer fills.
	wr.Flush()
	return wr
}

// Flush pushes any buffered bytes to the underlying sink. It's a no-op if w
// was constructed around an unbuffered io.Writer.
func (w *Writer) Flush() error {
	if w.err != nil {
		return w.err
	}
	if f, ok := w.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// Record writes one packet. Data may alias; pcapgo copies it into the frame.
// OrigLen defaults to len(Data); truncated captures set it explicitly.
func (w *Writer) Record(rec Record) error {
	if w.err != nil {
		return w.err
	}
	if len(rec.Data) > 1<<24 {
		w.err = fmt.Errorf("absurd record size %d", len(rec.Data))
		return w.err
	}
	ci := gopacket.CaptureInfo{
		Timestamp:     rec.Timestamp,
		CaptureLength: len(rec.Data),
		Length:        rec.OrigLen,
	}
	if ci.Length == 0 {
		ci.Length = len(rec.Data)
	}
	if err := w.gw.WritePacket(ci, rec.Data); err != nil {
		w.err = err
		return err
	}
	return nil
}

// Err returns the sticky write error, if any.
func (w *Writer) Err() error { return w.err }
