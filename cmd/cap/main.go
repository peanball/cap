// cap filters a pcap byte stream on stdin to a smaller pcap stream on
// stdout, keeping only TCP connections whose payloads match any of the
// configured matchers.
//
// Typical use: tcpdump -i any -w - 'tcp' | cap --sni .example.com > filtered.pcap
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/jessevdk/go-flags"

	"go.peanball.net/cap/internal/engine"
	"go.peanball.net/cap/internal/match"
	"go.peanball.net/cap/internal/pcap"
	"go.peanball.net/cap/internal/proxyhdr"
)

// Options declares all CLI flags for go-flags.
type Options struct {
	// I/O flags follow tcpdump/tshark conventions: -r for read (input file), //// -w for write (output file). Both default to stdin/stdout (-).
	Input  string `short:"r" long:"read"  default:"-" description:"input pcap file (- for stdin)"`
	Output string `short:"w" long:"write" default:"-" description:"output pcap file (- for stdout)"`

	Verbose bool `short:"v" long:"verbose" description:"log per-stream stats to stderr at EOF, and per-match progress lines"`

	Unbuffered bool `short:"U" long:"unbuffered" description:"flush output after every input packet instead of when the 1 MiB output buffer fills (use for live pipes)"`

	SNI []string `long:"sni" description:"match TLS ClientHello SNI (repeatable); leading '.' = suffix match"`

	Proxy           string   `long:"proxy" choice:"any" choice:"v1" choice:"v2" description:"match PROXY protocol header presence"`
	ProxyClientIP   []string `long:"proxy-client-ip"   description:"require PROXY header's client IP in this CIDR (repeatable; requires --proxy)"`
	ProxyClientPort []uint16 `long:"proxy-client-port" description:"require PROXY header's client port (repeatable; requires --proxy)"`

	TunnelIP   []string `long:"tunnel-ip"   description:"match only streams encapsulated in IPv4-in-IPv6 or IPv6-in-IPv6 tunnels with outer endpoints in this CIDR (repeatable)"`
	TunnelPort []uint16 `long:"tunnel-port" description:"match only streams encapsulated in IPv4-in-IPv6 or IPv6-in-IPv6 tunnels whose INNER TCP port equals this (repeatable)"`

	IdleTimeout time.Duration `long:"idle-timeout" default:"60s"   description:"evict unmatched streams idle longer than this"`
	MaxStreams  int           `long:"max-streams"  default:"100000" description:"cap concurrent streams"`
	Window      int           `long:"window"       default:"65536"  description:"reassembly window per direction (bytes)"`
	Linger      time.Duration `long:"linger"       default:"5s"     description:"keep forwarding late packets (final ACK, RSTs) of a closed matched connection this long"`

	Unpack bool `long:"unpack" description:"duplicate matched tunneled/PROXY-fronted packets: inner 4-in-6 packets reframed on the outer link, PROXY data packets rewritten to the asserted client tuple"`
}

// buildMatchers validates cross-flag constraints and assembles the matcher
// groups. Returns the byte matcher (or nil if only key matchers are set) and
// the key matchers.
func buildMatchers(o *Options) (match.Matcher, []match.KeyMatcher, error) {
	var bytes []match.Matcher

	if len(o.SNI) > 0 {
		m, err := match.NewSNI(o.SNI)
		if err != nil {
			return nil, nil, err
		}
		bytes = append(bytes, m)
	}

	if (len(o.ProxyClientIP) > 0 || len(o.ProxyClientPort) > 0) && o.Proxy == "" {
		return nil, nil, errors.New("--proxy-client-ip / --proxy-client-port require --proxy")
	}
	if o.Proxy != "" {
		var v proxyhdr.Version
		switch o.Proxy {
		case "any":
			v = proxyhdr.VersionAny
		case "v1":
			v = proxyhdr.VersionV1
		case "v2":
			v = proxyhdr.VersionV2
		}
		var cidrs []netip.Prefix
		for _, s := range o.ProxyClientIP {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, nil, fmt.Errorf("bad --proxy-client-ip %q: %w", s, err)
			}
			cidrs = append(cidrs, p)
		}
		bytes = append(bytes, match.NewProxy(v, cidrs, o.ProxyClientPort))
	}

	var keys []match.KeyMatcher
	if len(o.TunnelIP) > 0 {
		var cidrs []netip.Prefix
		for _, s := range o.TunnelIP {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, nil, fmt.Errorf("bad --tunnel-ip %q: %w", s, err)
			}
			cidrs = append(cidrs, p)
		}
		keys = append(keys, match.NewTunnelIP(cidrs))
	}
	if len(o.TunnelPort) > 0 {
		keys = append(keys, match.NewTunnelPort(o.TunnelPort))
	}

	if len(bytes) == 0 && len(keys) == 0 {
		return nil, nil, errors.New("at least one matcher required: --sni, --proxy, --tunnel-ip, or --tunnel-port")
	}

	var byteMatcher match.Matcher
	switch len(bytes) {
	case 0:
		byteMatcher = nil
	case 1:
		byteMatcher = bytes[0]
	default:
		byteMatcher = match.Or(bytes)
	}
	return byteMatcher, keys, nil
}

func main() {
	var o Options
	if _, err := flags.Parse(&o); err != nil {
		var ferr *flags.Error
		if errors.As(err, &ferr) && ferr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if err := run(&o); err != nil {
		fmt.Fprintln(os.Stderr, "cap:", err)
		os.Exit(2)
	}
}

// outBufSize is how much matched output accumulates before it is written
// when not running with --unbuffered.
const outBufSize = 1 << 20

func run(o *Options) error {
	matcher, keyMatchers, err := buildMatchers(o)
	if err != nil {
		return err
	}

	var in io.Reader = os.Stdin
	if o.Input != "-" {
		f, err := os.Open(o.Input)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	br := bufio.NewReaderSize(in, 1<<20)
	rdr, err := pcap.NewReader(br)
	if err != nil {
		return err
	}

	var out io.Writer = os.Stdout
	if o.Output != "-" {
		f, err := os.Create(o.Output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	return stream(o, matcher, keyMatchers, rdr, out, sigs, os.Exit)
}

// stream filters rdr into out. Output is block-buffered unless o.Unbuffered,
// in which case everything a packet produced is flushed before the next one
// is read. Buffered output is also flushed whenever a kept connection
// completes (see engine.FlushAdvised), at EOF, and, so an interrupted
// pipeline loses nothing, when a signal arrives on sigs: stream then calls
// exit(128+signal) after flushing. A nil sigs never fires.
func stream(o *Options, matcher match.Matcher, keyMatchers []match.KeyMatcher, rdr *pcap.Reader, out io.Writer, sigs <-chan os.Signal, exit func(int)) error {
	bw := bufio.NewWriterSize(out, outBufSize)
	// mu keeps the signal flush from landing between the two writes of a
	// record. It is held while a packet is processed, never while blocked
	// reading input.
	var mu sync.Mutex
	flush := func() error {
		mu.Lock()
		defer mu.Unlock()
		return bw.Flush()
	}
	defer func() { _ = flush() }() // final flush best-effort; errors surface via wr.Err() and the return path

	wr := pcap.NewWriter(bw, rdr)
	if err := wr.Err(); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	go func() {
		if sig, ok := <-sigs; ok {
			_ = flush() // stream returns the flush error on the main path
			exit(128 + int(sig.(syscall.Signal)))
		}
	}()

	eng, err := engine.New(engine.Config{
		Matcher:     matcher,
		KeyMatchers: keyMatchers,
		IdleTimeout: o.IdleTimeout,
		MaxStreams:  o.MaxStreams,
		WindowBytes: o.Window,
		Linger:      o.Linger,
		Unpack:      o.Unpack,
	}, wr)
	if err != nil {
		return err
	}
	defer eng.Close()

	for {
		rec, err := rdr.Record()
		if err == io.EOF {
			if o.Verbose {
				s := eng.Stats()
				fmt.Fprintf(os.Stderr, "stats: in=%d out=%d streams=%d kept=%d dropped=%d tainted=%d\n",
					s.PacketsIn, s.PacketsOut, s.StreamsTotal, s.StreamsKept, s.StreamsDrop, s.StreamsTaint)
				printECH(os.Stderr, s.ECHDropped, eng.ECHNames())
			}
			return flush()
		}
		if err != nil {
			return err
		}
		mu.Lock()
		err = eng.Process(rdr.LinkType(), rec.Timestamp, rec.Data)
		if advised := eng.FlushAdvised(); err == nil && (o.Unbuffered || advised) {
			err = bw.Flush()
		}
		mu.Unlock()
		if err != nil {
			return err
		}
	}
}

// maxECHLines caps how many outer SNIs the -v summary itemizes.
const maxECHLines = 10

// printECH reports dropped streams whose ClientHello offered ECH, grouped by
// outer SNI. It prints nothing when there were none.
func printECH(w io.Writer, total uint64, names []engine.ECHName) {
	if total == 0 {
		return
	}
	fmt.Fprintf(w, "ech: %d dropped stream(s) offered encrypted_client_hello (real or GREASE), by outer SNI:\n", total)
	for i, n := range names {
		if i == maxECHLines {
			fmt.Fprintf(w, "ech:   ... %d more name(s)\n", len(names)-i)
			break
		}
		sni := n.SNI
		if sni == "" {
			sni = "(no server_name)"
		}
		fmt.Fprintf(w, "ech:   %6d  %s\n", n.Count, sni)
	}
}
