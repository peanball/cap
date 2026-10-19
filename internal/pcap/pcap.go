// Package pcap reads and writes classic libpcap and pcapng capture files as a
// thin adapter over github.com/gopacket/gopacket/pcapgo — the actively
// maintained gopacket fork. It exists to give cap's engine one shape to
// consume regardless of how tcpdump or Wireshark emitted the file:
//   - Reader auto-detects classic pcap vs pcapng by the 4-byte magic and
//     normalizes the record stream (timestamps are time.Time, Data aliases
//     until next read, truncated tail reads as clean EOF).
//   - Writer is a format sum: classic pcap (pcapgo.Writer) or pcapng
//     (pcapgo.NgWriter) picked at construction. ng format lets us carry
//     metadata (filter expression per interface, per-packet comment on the
//     first kept packet of each stream).
//   - LinkType aliases layers.LinkType (uint16 in the fork; SLL2 and PKTAP
//     survive untouched).
package pcap

import (
	"bytes"
	"fmt"
	"io"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// LinkType is gopacket's layers.LinkType. The fork's v1.7.4 uses uint16, so
// SLL2 (276) and DLT_PKTAP (149) survive.
type LinkType = layers.LinkType

const (
	LinkEthernet   = layers.LinkTypeEthernet
	LinkNull       = layers.LinkTypeNull // DLT_NULL, BSD loopback (-i any lo0 on macOS)
	LinkRaw        = layers.LinkTypeRaw  // DLT_RAW, raw IPv4/IPv6
	LinkLinuxSLL   = layers.LinkTypeLinuxSLL
	LinkLinuxSLL2  = layers.LinkTypeLinuxSLL2 // 276
	LinkIPv4       = layers.LinkTypeIPv4
	LinkIPv6       = layers.LinkTypeIPv6
	LinkApplePKTAP = layers.LinkTypeApplePKTAP // 149, Darwin `-i any`
)

// Format identifies the on-disk container.
type Format int

const (
	FormatClassic Format = iota // 4-byte magic d4 c3 b2 a1 or a1 b2 c3 d4 (µs), or 4d 3c b2 a1 / a1 b2 3c 4d (ns)
	FormatNg                    // pcapng: 0a 0d 0d 0a (Section Header Block)
)

// FormatAuto pairs with Options.Ng: with FormatAuto output mirrors input.
const FormatAuto Format = -1

// Record is one captured packet from either container.
type Record struct {
	Timestamp time.Time
	Data      []byte
	// LinkType is the DLT of this packet's capture interface. Always set for
	// pcapng (which is per-interface); for classic pcap it matches
	// Reader.LinkType().
	LinkType LinkType
	// OrigLen is the captured frame's wire length. 0 = "as captured".
	OrigLen int
}

// -----------------------------------------------------------------------------
// Reader
// -----------------------------------------------------------------------------

// Reader iterates records from either classic pcap or pcapng.
type Reader struct {
	err    error
	format Format

	// classic
	rd *pcapgo.Reader

	// ng
	ngr *pcapgo.NgReader
}

// ngMagicBytes is the pcapng Section Header Block type, four bytes found at
// offset 0 of any pcapng stream regardless of declared endianness.
var ngMagicBytes = [4]byte{0x0a, 0x0d, 0x0d, 0x0a}

// linkTypeUnset is a non-assignable sentinel marking "no ancillary link type
// arrived on this packet". 0 is a valid DLT value (LinkNull/DLT_NULL), so the
// sentinel has to live outside that range.
const linkTypeUnset LinkType = ^LinkType(0)

// NewReader sniffs the first 4 bytes and chooses classic vs ng. On ng we
// enable WantMixedLinkType so each record's LinkType comes from the packet's
// own interface — pcapng is per-interface by design and the "first linktype"
// heuristic that libpcap inherited silently drops mismatched packets.
func NewReader(r io.Reader) (*Reader, error) {
	var magic [4]byte
	n, err := io.ReadFull(io.LimitReader(r, 4), magic[:])
	if err != nil && n < 4 {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	combined := io.MultiReader(bytes.NewReader(magic[:]), r)

	if magic == ngMagicBytes {
		ngr, err := pcapgo.NewNgReader(combined, pcapgo.NgReaderOptions{WantMixedLinkType: true})
		if err != nil {
			return nil, fmt.Errorf("read pcapng section header: %w", err)
		}
		return &Reader{ngr: ngr, format: FormatNg}, nil
	}

	rd, err := pcapgo.NewReader(combined)
	if err != nil {
		return nil, fmt.Errorf("read global header: %w", err)
	}
	return &Reader{rd: rd, format: FormatClassic}, nil
}

// Format reports the input container.
func (r *Reader) Format() Format { return r.format }

// LinkType is the dominant link type of the input. For classic pcap it is the
// global field; for pcapng it is the first interface's.
func (r *Reader) LinkType() LinkType {
	if r.rd != nil {
		return r.rd.LinkType()
	}
	return r.ngr.LinkType()
}

// Snaplen returns the dominant snap length for classic pcap inputs. For ng
// inputs it returns 0 (pcapng has snap length per interface; we don't track
// the dominant one, and ng output doesn't need it).
func (r *Reader) Snaplen() uint32 {
	if r.rd != nil {
		return r.rd.Snaplen()
	}
	return 0
}

// nanoResolution returns the dominant timestamp resolution so a pass-through
// classic writer can mirror it.
func (r *Reader) nanoResolution() bool {
	if r.rd != nil {
		return r.rd.Resolution() == gopacket.TimestampResolutionNanosecond
	}
	// pcapng timestamps resolve per interface; the first interface's is what
	// the dominant input is.
	return r.ngr.Resolution() == gopacket.TimestampResolutionNanosecond
}

// Record reads one packet. io.EOF at end. On error the same error sticks,
// and a truncated tail reads as clean EOF (pipe killed mid-write).
func (r *Reader) Record() (Record, error) {
	if r.err != nil {
		return Record{}, r.err
	}
	var (
		data []byte
		ci   gopacket.CaptureInfo
		err  error
	)
	var lt LinkType
	if r.rd != nil {
		data, ci, err = r.rd.ZeroCopyReadPacketData()
		lt = r.rd.LinkType()
	} else {
		data, ci, err = r.ngr.ZeroCopyReadPacketData()
		// WantMixedLinkType puts the per-interface link type in
		// AncillaryData[0]; fall back to the dominant (first) interface only if
		// absent. Distinct sentinel, since LinkRaw == 0 is a valid link type.
		lt = linkTypeUnset
		if len(ci.AncillaryData) > 0 {
			if alt, ok := ci.AncillaryData[0].(layers.LinkType); ok {
				lt = alt
			}
		}
		if lt == linkTypeUnset {
			lt = r.ngr.LinkType()
		}
	}
	if err != nil {
		if err == io.ErrUnexpectedEOF {
			r.err = io.EOF
			return Record{}, io.EOF
		}
		r.err = err
		return Record{}, err
	}
	return Record{
		Timestamp: ci.Timestamp,
		Data:      data,
		LinkType:  lt,
		OrigLen:   ci.Length,
	}, nil
}

// -----------------------------------------------------------------------------
// Writer
// -----------------------------------------------------------------------------

// Writer emits either container. Not safe for concurrent use.
type Writer struct {
	w      io.Writer
	err    error
	filter string // populated by WithFilterComment, used by ng IDBs

	// classic
	c *pcapgo.Writer

	// ng
	ng       *pcapgo.NgWriter
	linkToID map[LinkType]int
}

// WriterOption configures NewWriter.
type WriterOption func(*Writer)

// WithFilterComment places s into each ng IDB's `if_filter` field (and is
// ignored on classic output). Filter provenance lives at the interface
// level, not the section level, because mixed-interface files carry one
// filter per.
func WithFilterComment(s string) WriterOption { return func(w *Writer) { w.filter = s } }

// NewWriter mirrors rd: classic-in → classic-out, ng-in → ng-out with
// matching interfaces. If rd's input was ng with multiple link types, one IDB
// per link type is created on first write.
func NewWriter(w io.Writer, rd *Reader, opts ...WriterOption) *Writer {
	wr := &Writer{w: w}
	for _, o := range opts {
		o(wr)
	}
	if rd.format == FormatNg {
		if err := wr.startNg(rd.Snaplen()); err != nil {
			wr.err = err
		}
		return wr
	}
	wr.startClassic(rd.LinkType(), rd.Snaplen(), rd.nanoResolution())
	return wr
}

// NewWriterRaw constructs a writer with explicit output format and link type.
// Used for fresh pcap streams (testdata generation) and for `--ng=false`
// forcing classic output from ng input.
func NewWriterRaw(w io.Writer, link LinkType, snap uint32, nano bool, format Format, opts ...WriterOption) *Writer {
	wr := &Writer{w: w}
	for _, o := range opts {
		o(wr)
	}
	switch format {
	case FormatClassic:
		wr.startClassic(link, snap, nano)
	case FormatNg:
		if err := wr.startNg(snap); err != nil {
			wr.err = err
		}
	default:
		wr.err = fmt.Errorf("unknown format %v", format)
	}
	return wr
}

// filter is the comment each interface's `if_filter` field carries.
// (Set via WithFilterComment; not stored on classic writers.)

func (w *Writer) startClassic(link LinkType, snap uint32, nano bool) {
	if nano {
		w.c = pcapgo.NewWriterNanos(w.w)
	} else {
		w.c = pcapgo.NewWriter(w.w)
	}
	if err := w.c.WriteFileHeader(snap, link); err != nil {
		w.err = err
		return
	}
	// Flush eagerly so a downstream that opens the stream before any match
	// sees a valid pcap header.
	w.Flush()
}

// startNg writes the SHB and leaves interface creation to first write of each
// link type.
func (w *Writer) startNg(snap uint32) error {
	ng, err := pcapgo.NewNgWriterInterface(w.w, pcapgo.NgInterface{
		LinkType:   LinkEthernet, // placeholder; real IDB created lazily per link type
		SnapLength: snap,
	}, pcapgo.DefaultNgWriterOptions)
	if err != nil {
		return err
	}
	w.ng = ng
	w.linkToID = map[LinkType]int{}
	// Discard the placeholder IDB NewNgWriterInterface emitted; we re-create
	// them via ngID below.
	return nil
}

// ngID returns the interface ID for the given link type, adding one on first
// sight. `if_filter` carries the filter comment.
func (w *Writer) ngID(lt LinkType) (int, error) {
	if id, ok := w.linkToID[lt]; ok {
		return id, nil
	}
	id, err := w.ng.AddInterface(pcapgo.NgInterface{
		LinkType: lt,
		Filter:   w.filter, // optional comment, empty is fine
	})
	if err != nil {
		return -1, err
	}
	w.linkToID[lt] = id
	return id, nil
}

// filter: see WithFilterComment.
// (Stored here rather than on the struct to keep the surface small.)

// Flush pushes any buffered bytes to the underlying sink (bufio or the
// ngwriter's internal buffer).
func (w *Writer) Flush() error {
	if w.err != nil {
		return w.err
	}
	if w.ng != nil {
		return w.ng.Flush()
	}
	if f, ok := w.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

// Record writes one packet. LinkType selects the output interface for ng;
// for classic output it must equal the opening LinkType.
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
	if w.ng != nil {
		id, err := w.ngID(rec.LinkType)
		if err != nil {
			w.err = err
			return err
		}
		ci.InterfaceIndex = id
		if err := w.ng.WritePacket(ci, rec.Data); err != nil {
			w.err = err
			return err
		}
		return nil
	}
	if err := w.c.WritePacket(ci, rec.Data); err != nil {
		w.err = err
		return err
	}
	return nil
}

// RecordComment writes one packet with a per-packet comment. Only meaningful
// on ng output; on classic output it writes the packet unchanged.
func (w *Writer) RecordComment(rec Record, comment string) error {
	if w.err != nil {
		return w.err
	}
	if w.ng == nil {
		return w.Record(rec)
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
	id, err := w.ngID(rec.LinkType)
	if err != nil {
		w.err = err
		return err
	}
	ci.InterfaceIndex = id
	opts := pcapgo.NgPacketOptions{Comments: []string{comment}}
	if err := w.ng.WritePacketWithOptions(ci, rec.Data, opts); err != nil {
		w.err = err
		return err
	}
	return nil
}

// Err returns the sticky write error, if any.
func (w *Writer) Err() error { return w.err }
