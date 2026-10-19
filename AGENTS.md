# Repository Guidelines

## Project Overview

`cap` (module `go.peanball.net/cap`) filters a live or recorded **pcap stream** by TCP *content*. It reads classic pcap on stdin, reassembles each connection, and writes only the connections whose payload matches (TLS ClientHello SNI, PROXY protocol header, in-6 tunnel keys) as pcap on stdout. It exists because BPF decides per packet by header and cannot express "this TLS stream's SNI is `.example.com`".

```
tcpdump -i any -w - -U 'tcp' | cap -U --sni .example.com | tshark -r -
```

## Architecture & Data Flow

```
stdin -> pcap.Reader -> engine.Process(link, ts, data)
  decode (gopacket) -> tunnel peel -> flowKey -> e.streams lookup
    new stream:  KeyMatchers.ConsiderKey(StreamInfo) on first packet (reject = untracked)
    undecided:   packet copied to streamState.pending, fed to gopacket Assembler
                 -> streamState.ReassembledSG appends client->server bytes to buf
                 -> cfg.Matcher.Consider(buf) -> NeedMore | Match | NoMatch
    Match:       onMatch replays pending in order; later packets take the fast path
                 in Process and are written directly (assembler Accept returns false)
    NoMatch:     pending dropped; later packets of the stream dropped
    kept+closed: FIN from both sides or RST -> startLinger (stays in e.streams for
                 cfg.Linger) so stragglers are still forwarded, then evicted
  -> pcap.Writer -> bufio (1 MiB, owned by cmd/cap stream()) -> stdout
```

Every packet of a kept stream goes through Engine.emitPacket: verbatim frame
first, then (Config.Unpack only) unpack copies — in-6 tunnel inners (IPv4,
NextHeader 4; IPv6, NextHeader 41) reframed on the outer link, PROXY-fronted
data packets rewritten to the header's asserted 5-tuple. PROXY rewrite state
(header offsets, client SYN ISN, tuple) lives in Engine.proxy keyed by
flowKey; set in Process on the first SYN and in onMatch once the buffered
client prefix parses as a PROXY header.

Patterns to preserve:

- **Single-goroutine engine.** `Engine` is "single caller goroutine only". The only other goroutine is the signal handler in `cmd/cap/main.go:stream()`, serialised against `Process` by a mutex.
- **Matchers are pure functions of the growing buffer.** `match.Matcher.Consider(buf)` is called repeatedly with the client->server prefix; same `buf` must give the same `Verdict`; `NoMatch` is terminal. Composition: `match.Or` within one kind (repeated `--sni`), `match.And` across kinds. Stream-identity gates are separate `match.KeyMatcher`s (`keys.go`).
- **Packet time drives all timers.** Idle flush (1 Hz), linger sweep and tests use the packet `ts`, never the wall clock.
- **The engine never flushes output.** Flush policy lives in `cmd/cap` `stream()`: `-U` flushes after every input packet; otherwise it flushes on `eng.FlushAdvised()` (a kept connection closed, or a straggler after it), at EOF, and on SIGINT/SIGTERM (then `exit(128+sig)`).
- **Lingering applies only to matched streams.** Unmatched streams never linger and never advise a flush.
- **Everything is bounded.** `WindowBytes` (taint on overflow), `PendingBytesPerStream`, `MaxStreams`, `maxCHLen`, `maxECHNames` (1024). New per-peer state needs a bound.
- **Parser result style.** `tlsch.Parse` and `proxyhdr` return sentinel errors (`ErrNeedMore` = buffer more, `ErrNotTLS`/`ErrNotProxy` = never matches, `ErrTooBig`). Callers use `errors.Is`.

## Key Directories

- `cmd/cap/` CLI: `Options` struct, `buildMatchers`, `run` (opens files, signals), `stream` (loop, buffering, flushing), `printECH`.
- `internal/engine/` pipeline: `engine.go` (`Config`, `Stats`, `Process`, linger, ECH counters), `stream.go` (`streamState`, gopacket `StreamFactory`).
- `internal/match/` `Matcher`/`KeyMatcher` interfaces and the SNI, Proxy, tunnel matchers.
- `internal/tlsch/` first-record ClientHello parser: SNI plus outer ECH extension fields.
- `internal/proxyhdr/` PROXY v1/v2 parser. `internal/pcap/` classic pcap reader/writer (Reader.Record returns a slice aliased into an internal buffer — copy before retaining).
- `internal/unpack/` frame rewriters for kept streams: `Tunnel` (in-6 tunnels: copy the inner IPv4 or IPv6 packet onto the outer link) and `PROXY` (rewrite a data packet's 5-tuple to the PROXY header's, fixing lengths and checksums). Both are pure functions of one captured frame; engine-side state is in `engine/unpack.go`.
- `test/test.pcap`, `peanball.pcap` manual smoke fixtures (no Go test reads them). `internal/tcpasm/` is an empty leftover directory.

## Development Commands

```
go build -o cap ./cmd/cap             # root ./cap is a build artifact; rebuild, never edit
go vet ./...
gofmt -l .                            # currently prints nothing; keep it that way
go test -race ./...
go test -cover ./...
go run ./test                         # regenerate testdata/*.pcap + fixtures.sha256 (deterministic, no-op unless a scenario changed)
cap -r test/test.pcap --sni peanball.net | tshark -r -        # offline smoke
cap -v --sni peanball.net -r test/test.pcap -w /dev/null      # stats: in=1612 out=58 streams=67 kept=1 dropped=15
```

Live capture needs `-U` on **both** `tcpdump` and `cap`, otherwise each block-buffers and the downstream sees nothing until a buffer fills or input ends. `tcpdump` needs root. Convert pcapng first: `editcap -F pcap in.pcapng -`.

## Code Conventions & Common Patterns

- **Flags:** `go-flags` with struct tags only, declared in `Options` (`long:"linger" default:"5s" description:"..."`). A flag change touches the `Options` tag, `buildMatchers` (if it is a matcher), the README table **and** the README prose/examples.
- **Config defaults:** zero value means default, applied in `engine.New` (`if cfg.Linger <= 0 { ... }`). Document the default in the field comment and the README.
- **Errors:** wrap with `fmt.Errorf("...: %w", err)`; `main` prints `cap: <err>` and exits 2. Output write errors are sticky in `pcap.Writer`.
- **Dependency injection:** `engine.Config` injects matchers; `stream()` takes `sigs <-chan os.Signal` and `exit func(int)` so tests can drive signals without exiting.
- **State:** all per-connection state lives in `streamState`, indexed by the direction-normalised `flowKey` in `Engine.streams`. Removal goes through `Engine.evict`, which only deletes if the entry is still that stream.
- **Comments:** doc comments state the invariant or the reason (why a flag exists, what a counter does not mean), not what the code does. Match that when adding code.
- Dependencies: stdlib plus `gopacket` (decode, `reassembly`, classic-pcap and pcapng I/O via `pcapgo`) and `go-flags`. We use the actively maintained fork `github.com/gopacket/gopacket v1.7.4` (which decodes Linux SLL/SLL2, Apple PKTAP, and mixed-linktype pcapng natively; the archived `github.com/google/gopacket` at v1.1.19 has a uint8 LinkType that truncates SLL2 and an inverted Resolution()). Do not add others without need.

- pcap vs pcapng both directions: `internal/pcap.Reader` sniffs the 4-byte magic (0a 0d 0d 0a = ng Section Header Block) and enables `WantMixedLinkType` so each record carries its per-interface link type; pcapgo's libpcap-compatible default of "first interface wins" silently drops mismatched packets. `pcap.Writer` is a format sum. Output `Record.LinkType` is threaded through `Engine.Process` per packet so engine decoding and the writer's IDB pick the right link type for every packet. On ng output, `WithFilterComment` lands the string in each IDB's `if_filter` field; the engine emits an EPB `opt_comment` only on the first-match packet of each kept stream.

## Important Files

- `cmd/cap/main.go` entry point, flags, buffering and flush policy.
- `internal/engine/engine.go` `Process` fast paths, linger (`startLinger`, `sweepLingering`), `FlushAdvised`, ECH drop counters.
- `internal/engine/stream.go` `Accept`/`ReassembledSG`, where the matcher is consulted and verdicts are set.
- `internal/tlsch/tlsch.go` `Parse`; only the first TLS record, a ClientHello spanning records returns `ErrNotTLS`.
- `README.md` user-facing contract (flag tables, ECH behaviour, limits, known limitations).

## Runtime/Tooling Preferences

- Go toolchain new enough for `go 1.27.2` (`go.mod`; no `toolchain` line). Go modules only.
- `go.mod` lists all three requires as `// indirect` although gopacket and go-flags are imported directly; `golang.org/x/sys` is not imported. `go mod tidy` has not been run.
- Not a git repository. No Makefile, CI, lint config, `.gitignore`, LICENSE (README says "TBD") or SPDX headers.
- External tools are for manual runs only: `tcpdump`, `tshark`, `editcap`. Go tests need none and do not need root.

## Testing & QA

- Stdlib `testing` only (no testify). Table tests with `t.Run`; helpers call `t.Helper()`.
- **Whole-flow tests replay checked-in pcaps.** Scenarios tunneled SNI match, tunnel-IP gate, plain-vs-tunnel gating, fragmented ClientHello, 4-in-6 / 6-in-6 unpack, PROXY tuple rewrite live in `cmd/cap/testdata/` and `internal/engine/testdata/`, one `.pcap` per story plus a `fixtures.sha256` manifest beside them. The generator is `test/main.go` (`go run ./test` from the repo root) driving `internal/testgenpcap`; fixed epoch (`2026-01-01`) makes regeneration byte-identical, and `internal/testgenpcap.TestFixturesFresh` fails when file, manifest, or generator output disagree, so review diffs either rewrite the pair or the test pins the drift. Open a fixture in Wireshark to see the scenario a test asserts on.
- **Stepwise engine probes keep per-packet control, not per-package code.** Linger, reused tuple, RST handling, flush advice, ECH boundedness need assertions between individual packets, so they keep the `harness` and per-packet entry points (`harness.send`, `tick`) in `engine_test.go`; the frame/CH construction inside them goes through `internal/testgenpcap` like everything else. Frame and ClientHello synthesis (`buildTCPFrame`, `buildCH`, `buildTLSCH`, `eth`, `mkEth`, `mkIPv4TCP`, `mkIPv6`) is a thin alias or delegate over `testgenpcap` — never a private copy.
- Reusable test types: `stubMatcher` and `harness` (`open`, `send`, `tick`, `out`) in `internal/engine`; `countingWriter`, `whenDry`, `signalAfter` and `runStream` in `cmd/cap`.
- Deterministic: no sleeps. Time is simulated through packet timestamps (`harness.tick` advances engine time with a non-TCP packet); concurrency is synchronised with channels.
- Assert output by counting records with `pcap.NewReader` (`countRecords`) and by reading `Stats()`; do not compare against fixture files.
- Test comments name the invariant pinned (e.g. a signal must not strand buffered packets). Verify a new test by breaking the behaviour on a scratch copy and confirming it fails.
- `TestGoClientECH` parses a real `crypto/tls` ECH ClientHello over `net.Pipe`; prefer an independent implementation over hand-built bytes where one exists.
- Coverage (`go test -cover ./...`): tlsch 82.9%, proxyhdr 80.2%, pcap 72.8%, engine 68.7%, cmd/cap 25.2%, `internal/match` 0% (no tests; exercised only through `cmd/cap`).

## Known Engine Pitfalls

- **Kept streams are not exempt from idle eviction.** gopacket's idle flush (`--idle-timeout`, 60 s of packet time since the match) runs only while unmatched traffic is flowing; it ends the assembler connection and `onComplete` drops the stream, so an active kept connection stops being forwarded and its close/stragglers are lost. Do not rely on the "matched streams are exempt" comment in `Config`.
- **A reused 4-tuple within about 60 s of a match is not tracked.** The assembler pool still holds the old connection and ignores the new SYN. The SYN-on-lingering-stream guard only prevents the new packets leaking into the output.
- Mid-stream captures (no SYN seen) are skipped; `clientKnown` is set only from an observed SYN.
