// Package match defines the matcher interface consulted by the engine as
// stream bytes accumulate, and v1's concrete matchers.
package match

import (
	"errors"
	"net/netip"
	"strings"

	"go.peanball.net/cap/internal/proxyhdr"
	"go.peanball.net/cap/internal/tlsch"
)

// Verdict is a matcher's opinion after seeing some prefix of the client→server
// byte stream. NoMatch is terminal; NeedMore means ask again with more bytes.
type Verdict int

const (
	NeedMore Verdict = iota
	Match
	NoMatch
)

// Matcher inspects a stream and reports a Verdict. buf is the reassembled
// client→server payload from offset 0, growing monotonically across calls.
// Implementations must be deterministic in buf: same buf → same Verdict.
//
// A Matcher returning Match on a partially-buffered handshake is valid; the
// engine stops asking once Match is reached.
type Matcher interface {
	// Consider returns the current verdict.
	Consider(buf []byte) Verdict
}

// SNI matches a TLS ClientHello whose server_name equals one of the wanted
// names (case-folded) or, if the wanted name has a leading '.', any of its
// direct or deeper subdomains. Empty want list is invalid.
type SNI struct {
	exact  []string
	suffix []string // leading '.' kept for clarity; we strip before compare
}

// NewSNI splits want into exact and suffix sets. "example.com" → exact;
// ".example.com" → suffix; "*.example.com" is rejected (ambiguous with
// one-level-only DNS wildcards).
func NewSNI(want []string) (*SNI, error) {
	if len(want) == 0 {
		return nil, errors.New("empty SNI matcher")
	}
	s := &SNI{}
	for _, w := range want {
		w = strings.ToLower(w)
		if strings.HasPrefix(w, "*.") {
			return nil, errors.New("wildcard *. not supported; use .example.com for suffix match")
		}
		if strings.HasPrefix(w, ".") {
			s.suffix = append(s.suffix, w[1:])
		} else {
			s.exact = append(s.exact, w)
		}
	}
	return s, nil
}

func (m *SNI) Consider(buf []byte) Verdict {
	info, err := tlsch.Parse(buf)
	switch {
	case errors.Is(err, tlsch.ErrNeedMore):
		return NeedMore
	case err != nil:
		return NoMatch
	case info.SNI == "":
		return NoMatch
	}
	sni := info.SNI
	for _, e := range m.exact {
		if sni == e {
			return Match
		}
	}
	for _, s := range m.suffix {
		if strings.HasSuffix(sni, "."+s) {
			return Match
		}
	}
	return NoMatch
}

// Proxy matches the presence of a PROXY-protocol header at stream start.
// Version gates which wire form(s) count. Optional CIDR/port sets filter
// the original client fields carried in the header; empty sets pass.
type Proxy struct {
	version proxyhdr.Version
	cidrs   []netip.Prefix
	ports   map[uint16]struct{}
}

// NewProxy builds a Proxy matcher. cidrs/ports may be nil/empty (presence-only).
func NewProxy(v proxyhdr.Version, cidrs []netip.Prefix, ports []uint16) *Proxy {
	p := &Proxy{version: v, cidrs: cidrs}
	if len(ports) > 0 {
		p.ports = make(map[uint16]struct{}, len(ports))
		for _, port := range ports {
			p.ports[port] = struct{}{}
		}
	}
	return p
}

func (p *Proxy) Consider(buf []byte) Verdict {
	info, err := proxyhdr.Parse(buf)
	switch {
	case errors.Is(err, proxyhdr.ErrNeedMore):
		return NeedMore
	case err != nil:
		return NoMatch
	}
	if p.version != proxyhdr.VersionAny && info.Version != p.version {
		return NoMatch
	}
	if len(p.cidrs) > 0 {
		if !info.SrcIP.IsValid() {
			return NoMatch
		}
		ok := false
		for _, c := range p.cidrs {
			if c.Contains(info.SrcIP) {
				ok = true
				break
			}
		}
		if !ok {
			return NoMatch
		}
	}
	if len(p.ports) > 0 {
		if _, ok := p.ports[info.SrcPort]; !ok {
			return NoMatch
		}
	}
	return Match
}

// Or combines matchers with OR semantics: returns Match if any say Match,
// NoMatch only when every matcher is terminal NoMatch, else NeedMore.
type Or []Matcher

func (o Or) Consider(buf []byte) Verdict {
	anyNeed := false
	for _, m := range o {
		v := m.Consider(buf)
		switch v {
		case Match:
			return Match
		case NeedMore:
			anyNeed = true
		}
	}
	if anyNeed {
		return NeedMore
	}
	return NoMatch
}

// And combines matchers with AND semantics: Match iff all Match; NoMatch if
// any is terminal NoMatch; otherwise NeedMore (waiting on at least one).
type And []Matcher

func (a And) Consider(buf []byte) Verdict {
	anyNeed := false
	for _, m := range a {
		switch m.Consider(buf) {
		case NoMatch:
			return NoMatch
		case NeedMore:
			anyNeed = true
		}
	}
	if anyNeed {
		return NeedMore
	}
	return Match
}
