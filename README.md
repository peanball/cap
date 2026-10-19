# cap

Filter and process TCP streams on the fly. Reads a pcap stream from stdin, keeps only connections that match, writes the rest to stdout.

Unlike `tcpdump`'s BPF, which decides per-packet by header, `cap` reassembles each connection and matches on its *content*:

- TLS ClientHello SNI (TLS 1.2 and 1.3; see [Encrypted Client Hello](#encrypted-client-hello) for what ECH hides)
- PROXY protocol headers (v1 text + v2 binary), with original-client IP/port filters
- IPv4-in-IPv6 (NextHeader 4) and IPv6-in-IPv6 (NextHeader 41) tunnels, keyed on outer endpoints or inner TCP ports
- Unwrapping of tunnels (PROXY protocol and IP-in-IP) with copies of the tunneled stream injected for easier analysis

```
tcpdump -i any -w - -U 'tcp' | cap -U --sni .example.com | tshark -r -
```

`-U` is required on both tools for live capture: without it, tcpdump and `cap` block-buffer their output and downstream tools see nothing until the buffer fills or the input ends. See [I/O](#io).

## Install

```shell
go install go.peanball.net/cap/cmd/cap@latest
```

or `go build ./cmd/cap` from the repo.

## Matching

Multiple `--sni` flags are OR'd. Matchers of different kinds are AND'd: a stream must satisfy every configured group.

| Flag | What it matches |
|---|---|
| `--sni NAME` | TLS ClientHello SNI. Exact case-insensitive. Leading `.` means suffix, so `.example.com` matches `api.example.com` but not `notexample.com`. |
| `--proxy any\|v1\|v2` | Stream carries a PROXY protocol header. |
| `--proxy-client-ip CIDR` | PROXY header's original client IP in CIDR. Requires `--proxy`. |
| `--proxy-client-port PORT` | PROXY header's original client port. Requires `--proxy`. |
| `--tunnel-ip CIDR` | Stream is IPv4-in-IPv6 or IPv6-in-IPv6 (NextHeader 4 or 41) with a tunnel endpoint in CIDR. |
|`--tunnel-port PORT`|Same, matching the *inner* TCP port (in-6 tunnels have no outer ports).|
|`--ng MODE`|Output container: `auto` (mirror input — pcapng in, pcapng out), `true` (always pcapng, carries match provenance), `false` (always classic pcap). Default `auto`. See [I/O](#io).|

Examples:

```
# Whole domain incl. subdomains
cap --sni .example.com

# Several explicit hosts
cap --sni api.example.com --sni www.example.com

# Backend traffic where the LB saw specific original clients
cap --proxy v1 --proxy-client-ip 203.0.113.0/24

# Tunneled streams whose outer endpoint is in 2001:db8::/32, only HTTPS inside
cap --tunnel-ip 2001:db8::/32 --tunnel-port 443
```

## Encrypted Client Hello

With Encrypted Client Hello (ECH, [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849)) the client encrypts its real ClientHello and sends an outer one whose SNI is a shared `public_name`, typically one name for a whole CDN. `cap` reads only the outer ClientHello and cannot decrypt the inner one: that needs the server's ECH private key or the client's key log, and `cap` has neither.

What that means for `--sni`:

- **Real ECH**: `cap` sees the public name, so `--sni example.com` does not match and the stream is dropped.
- **GREASE ECH**: browsers send a fake ECH extension on connections where they hold no ECH config (RFC 9849 §6.2.1). The SNI stays real and matches normally.

Neither can be told apart from the packet alone, so with `-v` `cap` reports the dropped streams whose ClientHello offered ECH, grouped by outer SNI:

```
stats: in=12 out=3 streams=4 kept=1 dropped=3 tainted=0
ech: 2 dropped stream(s) offered encrypted_client_hello (real or GREASE), by outer SNI:
ech:        2  public.example
```

A name that dominates this list and is shared by many sites is a public name, i.e. real ECH. One-off names are GREASE on ordinary connections, dropped for unrelated reasons.

Options, none of which reveal the hidden origin:

- Keep the whole bucket by matching the public name, e.g. `cap --sni cloudflare-ech.com` for Cloudflare-fronted sites. This keeps every origin behind that name; `cap` cannot narrow it.
- Disable ECH on clients you control. Chrome has the `EncryptedClientHelloEnabled` enterprise policy, which Google documents as a temporary control. RFC 9849 §8.2 names disabling ECH by policy as the approach for managed networks.

## I/O

Input and output flags follow `tcpdump` where possible.

`-r FILE`: input pcap (default `-` = stdin)
`-w FILE`: output pcap (default `-` = stdout)

`-r`/`-w` follow tcpdump/tshark conventions. Inputs are classic pcap or pcapng (auto-detected from the file magic; per-interface link types are honoured, so merged `mergecap` outputs work). Link types handled: Ethernet / Linux SLL / Linux SLL2 / raw IPv4 / raw IPv6 / Apple PKTAP (Darwin `tcpdump -i any`).

The output container follows the input by default. With pcapng input, pcapng comes out, with one interface description per observed link type so mixed captures survive the filter. Forcible via `--ng=true` (always pcapng, even on classic input) or `--ng=false` (always classic, even on pcapng input). Classic output carries no metadata. pcapng output carries two pieces of provenance:

- IDB `if_filter` on every interface — the matcher flags cap ran with, e.g. `--sni .peanball.net --tunnel-port 443`. Visible in Wireshark under Statistics → Capture File Properties.
- EPB `opt_comment` on the first packet that flipped a stream to *kept* — same string. Visible in Wireshark's Packet Comments column.

Output preserves input link type (per packet, for pcapng) and packet timestamps verbatim.

All relevant packets of a stream (TCP handshake, ClientHello, ...) are buffered per-stream and replayed in timestamp order on the first match. After a match, the rest of the TCP stream is is forwarded as it arrives.

When a matched connection closes (FIN from both sides, or RST), it is removed from the buffer. Because straggling packets, or packets introduced by proxies can arrive after `FIN` or `RST`, `cap` keeps forwarding such late packets (the final ACK, RSTs, retransmitted FINs) for a time configured via `--linger`, so the filtered capture includes all such artifacts.

`-U` / `--unbuffered`: flush output after every input packet, so a downstream reader sees a match as soon as it is decided. Without it, output is block-buffered (1 MiB) for throughput and written when the buffer fills, when a matched connection closes (and again for each late packet after it), at EOF, or on SIGINT/SIGTERM (`cap` flushes, then exits with 128+signal). Connections that are still open stay buffered, so use `-U` whenever something is reading `cap`'s output live and long-lived connections matter.

## Unpacking

`--unpack` duplicates packets of *matched* streams so hidden parts of the envelope become visible next to the verbatim frames:

- **In-6 tunnels** (NextHeader 4 for IPv4, 41 for IPv6): each outer packet is followed by a copy of the inner packet, reframed on the outer link layer (outer MACs kept, protocol field rewritten to the inner IP version).
- **PROXY-fronted connections**: every data packet after the PROXY header is followed by a copy whose IP addresses and ports are the ones the PROXY header asserts (the real client and the original destination), with checksums recomputed. The PROXY header packet itself is emitted verbatim only; header-less control packets (bare ACKs) get no copy.

The verbatim frame always comes first, so the output reads as two stacked views of the same on-wire byte sequence. Unpacked copies inherit the outer packet's timestamp. Raw IP capture link types carry no protocol field to rewrite, so tunnel unpacking only applies to link types with one (Ethernet, SLL, SLL2).

## Limits

Defaults are generous; hit them and `--verbose` (`-v`) shows counters on stderr at EOF.

| Flag | Default | Effect |
|---|---|---|
| `--idle-timeout` | 60s | Streams with no packet progress this long are evicted. |
| `--max-streams` | 100000 | Cap on concurrently tracked connections. Past this, new streams are dropped immediately. |
| `--window` | 65536 | Bytes per direction kept for matcher input. Streams needing more are dropped. |
| `--linger` | 5s | How long a closed matched connection keeps forwarding late packets (packet time). Lingering streams count toward `--max-streams`. |

Eviction covers idle streams, FIN+FIN, RST, and over-cap new streams. Memory per unmatched stream is bounded by the window + retained pre-match packets (≤4 MiB per stream hard cap).

## Known limitations

- TLS 1.3 with ECH carries only the public name as SNI; `cap` cannot see through it. See [Encrypted Client Hello](#encrypted-client-hello).
- Classic pcap and pcapng only; no older libpcap variants (snoop etc.).
- Mid-stream captures (SYN not observed) are skipped: there is no safe way to attribute client/server direction.
- IPv4 fragments are not reassembled. First fragments decode; subsequent fragments are dropped silently.

## License

Apache License 2.0, see [LICENSE](LICENSE).
