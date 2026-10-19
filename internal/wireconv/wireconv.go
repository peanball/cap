// Package wireconv converts length values (int) to the widths their wire
// field carries (byte/uint16/uint32). Every destination field is
// protocol-defined: a CH body's 24-bit handshake length, an IPv4 Total
// Length, a pseudo-header TCP length, a PROXY v2 8-bit tail, a sequence
// number. gosec's conversion analysis (G115) flags every direct narrowing;
// routing them through here lets the SSA range resolver see one guarded cast
// at the top of each function instead of a bare conversion in every caller.
//
// A panic means the caller produced something the protocol cannot express —
// a fixture builder bug, or captured bytes that lied about their length.
// Either is a programming error, not runtime data, so panic is correct.
// Named after regexp.MustCompile: callers must prove the input fits.
package wireconv

import "fmt"

// MustUint8 returns v as byte, panic on lossy conversion.
func MustUint8(v int) byte {
	if v < 0 || v > 0xff {
		panic(fmt.Sprintf("testcast: %d overflows an 8-bit wire field", v))
	}
	return byte(v)
}

// MustUint16 returns v as uint16, panic on lossy conversion.
func MustUint16(v int) uint16 {
	if v < 0 || v > 0xffff {
		panic(fmt.Sprintf("testcast: %d overflows a 16-bit wire field", v))
	}
	return uint16(v)
}

// MustUint32 returns v as uint32, panic on lossy conversion.
func MustUint32(v int) uint32 {
	if v < 0 || v > 0xffffffff {
		panic(fmt.Sprintf("testcast: %d overflows a 32-bit wire field", v))
	}
	return uint32(v)
}
