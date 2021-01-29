// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file contains the Go wrapper for the constant-time, 64-bit assembly
// implementation of sm2 curve. The optimizations performed here are described in
// detail in:
// S.Gueron and V.Krasnov, "Fast prime field elliptic-curve cryptography with
//                          256-bit primes"
// http://link.springer.com/article/10.1007%2Fs13389-014-0090-x
// https://eprint.iacr.org/2013/816.pdf

// +build amd64

package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	lru "github.com/hashicorp/golang-lru"
	"github.com/littlegirlpppp/gmsm/sm3"
	"github.com/status-im/keycard-go/hexutils"
	"io"
	"math/big"
	"sync"
)

type (
	p256Point struct {
		xyz [12]uint64
	}
)

// Functions implemented in sm2p256_amd64.s
// Montgomery multiplication modulo P256
func sm2p256Mul(res, in1, in2 []uint64)
func p256TestMul(res, in1, in2 []uint64)

// Montgomery square modulo P256
func sm2p256Sqr(res, in []uint64)

// Montgomery multiplication by 1
func sm2p256FromMont(res, in []uint64)

// iff cond == 1  val <- -val
func sm2p256NegCond(val []uint64, cond int)

// if cond == 0 res <- b; else res <- a
func sm2p256MovCond(res, a, b []uint64, cond int)

// Endianness swap
func sm2p256BigToLittle(res []uint64, in []byte)
func sm2p256LittleToBig(res []byte, in []uint64)

// Constant time table access
func sm2p256Select(point, table []uint64, idx int)
func sm2p256SelectBase(point, table []uint64, idx int)

// Montgomery multiplication modulo Ord(G)
func sm2p256OrdMul(res, in1, in2 []uint64)

// Montgomery square modulo Ord(G), repeated n times
func sm2p256OrdSqr(res, in []uint64, n int)

// Point add with in2 being affine point
// If sign == 1 -> in2 = -in2
// If sel == 0 -> res = in1
// if zero == 0 -> res = in2
func sm2p256PointAddAffineAsm(res, in1, in2 []uint64, sign, sel, zero int)

// Point add
func sm2p256PointAddAsm(res, in1, in2 []uint64) int

// Point double
func sm2p256PointDoubleAsm(res, in []uint64)

//Test Internal Func
func sm2p256TestSubInternal(res, in1, in2 []uint64)
func sm2p256TestMulInternal(res, in1, in2 []uint64)
func sm2p256TestMulBy2Inline(res, in1 []uint64)
func sm2p256TestSqrInternal(res, in1 []uint64)
func sm2p256TestAddInline(res, in1, in2 []uint64)

func (curve sm2P256Curve) Inverse(k *big.Int) *big.Int {
	if k.Sign() < 0 {
		// This should never happen.
		k = new(big.Int).Neg(k)
	}

	if k.Cmp(sm2P256.N) >= 0 {
		// This should never happen.
		k = new(big.Int).Mod(k, sm2P256.N)
	}

	// table will store precomputed powers of x. The four words at index
	// 4×i store x^(i+1).
	var table [4 * 15]uint64

	x := make([]uint64, 4)
	fromBig(x[:], k)
	// This code operates in the Montgomery domain where R = 2^256 mod n
	// and n is the order of the scalar field. (See initP256 for the
	// value.) Elements in the Montgomery domain take the form a×R and
	// multiplication of x and y in the calculates (x × y × R^-1) mod n. RR
	// is R×R mod n thus the Montgomery multiplication x and RR gives x×R,
	// i.e. converts x into the Montgomery domain.
	//	RR := []uint64{0x83244c95be79eea2, 0x4699799c49bd6fa6, 0x2845b2392b6bec59, 0x66e12d94f3d95620}
	RR := []uint64{0x901192AF7C114F20, 0x3464504ADE6FA2FA, 0x620FC84C3AFFE0D4, 0x1EB5E412A22B3D3B}

	sm2p256OrdMul(table[:4], x, RR)

	// Prepare the table, no need in constant time access, because the
	// power is not a secret. (Entry 0 is never used.)
	for i := 2; i < 16; i += 2 {
		sm2p256OrdSqr(table[4*(i-1):], table[4*((i/2)-1):], 1)
		sm2p256OrdMul(table[4*i:], table[4*(i-1):], table[:4])
	}

	x[0] = table[4*14+0] // f
	x[1] = table[4*14+1]
	x[2] = table[4*14+2]
	x[3] = table[4*14+3]

	sm2p256OrdSqr(x, x, 4)
	sm2p256OrdMul(x, x, table[4*14:4*14+4]) // ff
	t := make([]uint64, 4, 4)
	t[0] = x[0]
	t[1] = x[1]
	t[2] = x[2]
	t[3] = x[3]

	sm2p256OrdSqr(x, x, 8)
	sm2p256OrdMul(x, x, t) // ffff
	t[0] = x[0]
	t[1] = x[1]
	t[2] = x[2]
	t[3] = x[3]

	sm2p256OrdSqr(x, x, 16)
	sm2p256OrdMul(x, x, t) // ffffffff
	t[0] = x[0]
	t[1] = x[1]
	t[2] = x[2]
	t[3] = x[3]

	sm2p256OrdSqr(x, x, 64) // ffffffff0000000000000000
	sm2p256OrdMul(x, x, t)  // ffffffff00000000ffffffff
	sm2p256OrdSqr(x, x, 32) // ffffffff00000000ffffffff00000000
	sm2p256OrdMul(x, x, t)  // ffffffff00000000ffffffffffffffff

	// Remaining 32 windows
	expLo := [32]byte{0xb, 0xc, 0xe, 0x6, 0xf, 0xa, 0xa, 0xd, 0xa, 0x7, 0x1, 0x7, 0x9, 0xe, 0x8, 0x4, 0xf, 0x3, 0xb, 0x9, 0xc, 0xa, 0xc, 0x2, 0xf, 0xc, 0x6, 0x3, 0x2, 0x5, 0x4, 0xf}
	for i := 0; i < 32; i++ {
		sm2p256OrdSqr(x, x, 4)
		sm2p256OrdMul(x, x, table[4*(expLo[i]-1):])
	}

	// Multiplying by one in the Montgomery domain converts a Montgomery
	// value out of the domain.
	one := []uint64{1, 0, 0, 0}
	sm2p256OrdMul(x, x, one)

	xOut := make([]byte, 32)
	sm2p256LittleToBig(xOut, x)
	return new(big.Int).SetBytes(xOut)
}

// fromBig converts a *big.Int into a format used by this code.
func fromBig(out []uint64, big *big.Int) {
	for i := range out {
		out[i] = 0
	}

	for i, v := range big.Bits() {
		out[i] = uint64(v)
	}
}

// p256GetScalar endian-swaps the big-endian scalar value from in and writes it
// to out. If the scalar is equal or greater than the order of the group, it's
// reduced modulo that order.
func p256GetScalar(out []uint64, in []byte) {
	n := new(big.Int).SetBytes(in)

	if n.Cmp(sm2P256.N) >= 0 {
		n.Mod(n, sm2P256.N)
	}
	fromBig(out, n)
}

// sm2p256Mul operates in a Montgomery domain with R = 2^256 mod p, where p is the
// underlying field of the curve. (See initP256 for the value.) Thus rr here is
// R×R mod p. See comment in Inverse about how this is used.
var rr = []uint64{0x0000000200000003, 0x00000002FFFFFFFF, 0x0000000100000001, 0x0000000400000002}

func maybeReduceModP(in *big.Int) *big.Int {
	if in.Cmp(sm2P256.P) < 0 {
		return in
	}
	return new(big.Int).Mod(in, sm2P256.P)
}


// uint64IsZero returns 1 if x is zero and zero otherwise.
func uint64IsZero(x uint64) int {
	x = ^x
	x &= x >> 32
	x &= x >> 16
	x &= x >> 8
	x &= x >> 4
	x &= x >> 2
	x &= x >> 1
	return int(x & 1)
}

// scalarIsZero returns 1 if scalar represents the zero value, and zero
// otherwise.
func scalarIsZero(scalar []uint64) int {
	return uint64IsZero(scalar[0] | scalar[1] | scalar[2] | scalar[3])
}

func (p *p256Point) p256PointToAffine() (x, y *big.Int) {
	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	p256Inverse(zInv, p.xyz[8:12])
	sm2p256Sqr(zInvSq, zInv)
	sm2p256Mul(zInv, zInv, zInvSq)

	sm2p256Mul(zInvSq, p.xyz[0:4], zInvSq)
	sm2p256Mul(zInv, p.xyz[4:8], zInv)

	sm2p256FromMont(zInvSq, zInvSq)
	sm2p256FromMont(zInv, zInv)

	xOut := make([]byte, 32)
	yOut := make([]byte, 32)
	sm2p256LittleToBig(xOut, zInvSq)
	sm2p256LittleToBig(yOut, zInv)

	return new(big.Int).SetBytes(xOut), new(big.Int).SetBytes(yOut)
}

// CopyConditional copies overwrites p with src if v == 1, and leaves p
// unchanged if v == 0.
func (p *p256Point) CopyConditional(src *p256Point, v int) {
	pMask := uint64(v) - 1
	srcMask := ^pMask

	for i, n := range p.xyz {
		p.xyz[i] = (n & pMask) | (src.xyz[i] & srcMask)
	}
}

func p256Inverse(out, in []uint64) {

	var stack [10 * 4]uint64
	p2 := stack[4*0 : 4*0+4]
	p4 := stack[4*1 : 4*1+4]
	p8 := stack[4*2 : 4*2+4]
	p16 := stack[4*3 : 4*3+4]
	p32 := stack[4*4 : 4*4+4]

	p3 := stack[4*5 : 4*5+4]
	p7 := stack[4*6 : 4*6+4]
	p15 := stack[4*7 : 4*7+4]
	p31 := stack[4*8 : 4*8+4]

	sm2p256Sqr(out, in) //2^1

	sm2p256Mul(p2, out, in) // 2^2-2^0
	sm2p256Sqr(out, p2)
	sm2p256Mul(p3, out, in)
	sm2p256Sqr(out, out)
	sm2p256Mul(p4, out, p2) // f*p 2^4-2^0

	sm2p256Sqr(out, p4)
	sm2p256Sqr(out, out)
	sm2p256Sqr(out, out)
	sm2p256Mul(p7, out, p3)
	sm2p256Sqr(out, out)
	sm2p256Mul(p8, out, p4) // ff*p 2^8-2^0

	sm2p256Sqr(out, p8)

	for i := 0; i < 6; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(p15, out, p7)
	sm2p256Sqr(out, out)
	sm2p256Mul(p16, out, p8) // ffff*p 2^16-2^0

	sm2p256Sqr(out, p16)
	for i := 0; i < 14; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(p31, out, p15)
	sm2p256Sqr(out, out)
	sm2p256Mul(p32, out, p16) // ffffffff*p 2^32-2^0

	//(2^31-1)*2^33+2^32-1
	sm2p256Sqr(out, p31)
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)

	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)
	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)
	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)
	//x*2^32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}

	//x*2^32+p32
	for i := 0; i < 32; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p32)

	//x*2^16+p16
	for i := 0; i < 16; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p16)

	//x*2^8+p8
	for i := 0; i < 8; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p8)

	//x*2^4+p4
	for i := 0; i < 4; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p4)

	//x*2^2+p2
	for i := 0; i < 2; i++ {
		sm2p256Sqr(out, out)
	}
	sm2p256Mul(out, out, p2)

	sm2p256Sqr(out, out)
	sm2p256Sqr(out, out)
	sm2p256Mul(out, out, in)
}

func (p *p256Point) p256StorePoint(r *[16 * 4 * 3]uint64, index int) {
	copy(r[index*12:], p.xyz[:])
}

func boothW5(in uint) (int, int) {
	var s uint = ^((in >> 5) - 1)
	var d uint = (1 << 6) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}

func boothW7(in uint) (int, int) {
	var s uint = ^((in >> 7) - 1)
	var d uint = (1 << 8) - in - 1
	d = (d & s) | (in & (^s))
	d = (d >> 1) + (d & 1)
	return int(d), int(s & 1)
}
var (
	p256Precomputed *[37][64 * 8]uint64
	precomputeOnce  sync.Once
)
func initTable() {
	p256Precomputed = new([37][64 * 8]uint64)

	/*	basePoint := []uint64{
		0x79e730d418a9143c, 0x75ba95fc5fedb601, 0x79fb732b77622510, 0x18905f76a53755c6,
		0xddf25357ce95560a, 0x8b4ab8e4ba19e45c, 0xd2e88688dd21f325, 0x8571ff1825885d85,
		0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe,
	}*/
	basePoint := []uint64{
		0x61328990F418029E, 0x3E7981EDDCA6C050, 0xD6A1ED99AC24C3C3, 0x91167A5EE1C13B05,
		0xC1354E593C2D0DDD, 0xC1F5E5788D3295FA, 0x8D4CFB066E2A48F8, 0x63CD65D481D735BD,
		0x0000000000000001, 0x00000000FFFFFFFF, 0x0000000000000000, 0x0000000100000000,
	}
	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, basePoint)

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	for j := 0; j < 64; j++ {
		copy(t1, t2)
		for i := 0; i < 37; i++ {
			// The window size is 7 so we need to double 7 times.
			if i != 0 {
				for k := 0; k < 7; k++ {
					sm2p256PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256Inverse(zInv, t1[8:12])
			sm2p256Sqr(zInvSq, zInv)
			sm2p256Mul(zInv, zInv, zInvSq)

			sm2p256Mul(t1[:4], t1[:4], zInvSq)
			sm2p256Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], basePoint[8:12])
			// Update the table entry
			copy(p256Precomputed[i][j*8:], t1[:8])
		}
		if j == 0 {
			sm2p256PointDoubleAsm(t2, basePoint)
		} else {
			sm2p256PointAddAsm(t2, t2, basePoint)
		}
	}
}

func (p *p256Point) p256BaseMult(scalar []uint64) {
	precomputeOnce.Do(initTable)

	wvalue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wvalue))
	sm2p256SelectBase(p.xyz[0:8], p256Precomputed[0][0:], sel)
	sm2p256NegCond(p.xyz[4:8], sign)

	// (This is one, in the Montgomery domain.)
	//p.xyz[8] = 0x0000000000000001
	//p.xyz[9] = 0xffffffff00000000
	//p.xyz[10] = 0xffffffffffffffff
	//p.xyz[11] = 0x00000000fffffffe
	p.xyz[8] = 0x0000000000000001
	p.xyz[9] = 0x00000000FFFFFFFF
	p.xyz[10] = 0x0000000000000000
	p.xyz[11] = 0x0000000100000000
	var t0 p256Point
	// (This is one, in the Montgomery domain.)
	//t0.xyz[8] = 0x0000000000000001
	//t0.xyz[9] = 0xffffffff00000000
	//t0.xyz[10] = 0xffffffffffffffff
	//t0.xyz[11] = 0x00000000fffffffe
	t0.xyz[8] = 0x0000000000000001
	t0.xyz[9] = 0x00000000FFFFFFFF
	t0.xyz[10] = 0x0000000000000000
	t0.xyz[11] = 0x0000000100000000
	index := uint(6)
	zero := sel

	for i := 1; i < 37; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0xff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0xff
		}
		index += 7
		sel, sign = boothW7(uint(wvalue))
		sm2p256SelectBase(t0.xyz[0:8], p256Precomputed[i][0:], sel)
		sm2p256PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0.xyz[0:8], sign, sel, zero)
		zero |= sel
	}
}

func (p *p256Point) p256ScalarMult(scalar []uint64) {
	// precomp is a table of precomputed points that stores powers of p
	// from p^1 to p^16.
	var precomp [16 * 4 * 3]uint64
	var t0, t1, t2, t3 p256Point

	// Prepare the table
	p.p256StorePoint(&precomp, 0) // 1

	sm2p256PointDoubleAsm(t0.xyz[:], p.xyz[:])
	sm2p256PointDoubleAsm(t1.xyz[:], t0.xyz[:])
	sm2p256PointDoubleAsm(t2.xyz[:], t1.xyz[:])
	sm2p256PointDoubleAsm(t3.xyz[:], t2.xyz[:])
	t0.p256StorePoint(&precomp, 1)  // 2
	t1.p256StorePoint(&precomp, 3)  // 4
	t2.p256StorePoint(&precomp, 7)  // 8
	t3.p256StorePoint(&precomp, 15) // 16

	sm2p256PointAddAsm(t0.xyz[:], t0.xyz[:], p.xyz[:])
	sm2p256PointAddAsm(t1.xyz[:], t1.xyz[:], p.xyz[:])
	sm2p256PointAddAsm(t2.xyz[:], t2.xyz[:], p.xyz[:])
	t0.p256StorePoint(&precomp, 2) // 3
	t1.p256StorePoint(&precomp, 4) // 5
	t2.p256StorePoint(&precomp, 8) // 9

	sm2p256PointDoubleAsm(t0.xyz[:], t0.xyz[:])
	sm2p256PointDoubleAsm(t1.xyz[:], t1.xyz[:])
	t0.p256StorePoint(&precomp, 5) // 6
	t1.p256StorePoint(&precomp, 9) // 10

	sm2p256PointAddAsm(t2.xyz[:], t0.xyz[:], p.xyz[:])
	sm2p256PointAddAsm(t1.xyz[:], t1.xyz[:], p.xyz[:])
	t2.p256StorePoint(&precomp, 6)  // 7
	t1.p256StorePoint(&precomp, 10) // 11

	sm2p256PointDoubleAsm(t0.xyz[:], t0.xyz[:])
	sm2p256PointDoubleAsm(t2.xyz[:], t2.xyz[:])
	t0.p256StorePoint(&precomp, 11) // 12
	t2.p256StorePoint(&precomp, 13) // 14

	sm2p256PointAddAsm(t0.xyz[:], t0.xyz[:], p.xyz[:])
	sm2p256PointAddAsm(t2.xyz[:], t2.xyz[:], p.xyz[:])
	t0.p256StorePoint(&precomp, 12) // 13
	t2.p256StorePoint(&precomp, 14) // 15

	// Start scanning the window from top bit
	index := uint(254)
	var sel, sign int

	wvalue := (scalar[index/64] >> (index % 64)) & 0x3f
	sel, _ = boothW5(uint(wvalue))

	sm2p256Select(p.xyz[0:12], precomp[0:], sel)
	zero := sel

	for index > 4 {
		index -= 5
		sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
		sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])

		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0x3f
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0x3f
		}

		sel, sign = boothW5(uint(wvalue))

		sm2p256Select(t0.xyz[0:], precomp[0:], sel)
		sm2p256NegCond(t0.xyz[4:8], sign)
		sm2p256PointAddAsm(t1.xyz[:], p.xyz[:], t0.xyz[:])
		sm2p256MovCond(t1.xyz[0:12], t1.xyz[0:12], p.xyz[0:12], sel)
		sm2p256MovCond(p.xyz[0:12], t1.xyz[0:12], t0.xyz[0:12], zero)
		zero |= sel
	}

	sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])
	sm2p256PointDoubleAsm(p.xyz[:], p.xyz[:])

	wvalue = (scalar[0] << 1) & 0x3f
	sel, sign = boothW5(uint(wvalue))

	sm2p256Select(t0.xyz[0:], precomp[0:], sel)
	sm2p256NegCond(t0.xyz[4:8], sign)
	sm2p256PointAddAsm(t1.xyz[:], p.xyz[:], t0.xyz[:])
	sm2p256MovCond(t1.xyz[0:12], t1.xyz[0:12], p.xyz[0:12], sel)
	sm2p256MovCond(p.xyz[0:12], t1.xyz[0:12], t0.xyz[0:12], zero)
}

func Hexprint(in []byte) {
	for i := 0; i < len(in); i++ {
		fmt.Printf("%02x", in[i])
	}
	fmt.Println()
}

func AffineToP256Point(x, y *big.Int) (out p256Point) {
	z, _ := new(big.Int).SetString("0100000000000000000000000000000000FFFFFFFF0000000000000001", 16)
	p, _ := new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)
	tmpx, _ := new(big.Int).SetString("0", 16)
	tmpy, _ := new(big.Int).SetString("0", 16)
	tmpx.Mul(x, z)
	tmpy.Mul(y, z)
	tmpx.Mod(tmpx, p)
	tmpy.Mod(tmpy, p)
	fromBig(out.xyz[0:4], tmpx)
	fromBig(out.xyz[4:8], tmpy)
	fromBig(out.xyz[8:12], z)
	return out
}

func Uint64ToAffine(in []uint64) (x, y *big.Int) {
	var r p256Point
	for i := 0; i < 12; i++ {
		r.xyz[i] = in[i]
	}
	tmpx, tmpy := r.p256PointToAffine()
	return tmpx, tmpy
}


func getZ(pub *PublicKey) []byte {
	return getZById(pub, []byte("1234567812345678"))
}
func getZById(pub *PublicKey, id []byte) []byte {
	c := P256Sm2()
	var lena = uint16(len(id) * 8) //bit len of IDA
	var ENTLa = []byte{byte(lena >> 8), byte(lena)}
	var z = make([]byte, 0, 1024)

	//判断公钥x,y坐标长度是否小于32字节，若小于则在前面补0
	xBuf := pub.X.Bytes()
	yBuf := pub.Y.Bytes()

	xPadding := make([]byte, 32)
	yPadding := make([]byte, 32)

	if n := len(xBuf); n < 32 {
		xBuf = append(xPadding[:32-n], xBuf...)
	}

	if n := len(yBuf); n < 32 {
		yBuf = append(yPadding[:32-n], yBuf...)
	}

	var SM2PARAM_A, _ = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16)

	z = append(z, ENTLa...)
	z = append(z, id...)
	z = append(z, SM2PARAM_A.Bytes()...)
	z = append(z, c.Params().B.Bytes()...)
	z = append(z, c.Params().Gx.Bytes()...)
	z = append(z, c.Params().Gy.Bytes()...)
	z = append(z, xBuf...)
	z = append(z, yBuf...)

	//h := sm3.New()
	hash := sm3.Sm3Sum(z)
	return hash[:]
}


//precompute public key table
func  InitPubKeyTable(x,y *big.Int) (Precomputed *PCom) {
	Precomputed = new(PCom)

	var r p256Point
	fromBig(r.xyz[0:4], maybeReduceModP(x))
	fromBig(r.xyz[4:8], maybeReduceModP(y))
	sm2p256Mul(r.xyz[0:4], r.xyz[0:4], rr[:])
	sm2p256Mul(r.xyz[4:8], r.xyz[4:8], rr[:])
	r.xyz[8] = 0x0000000000000001
	r.xyz[9] = 0x00000000FFFFFFFF
	r.xyz[10] = 0x0000000000000000
	r.xyz[11] = 0x0000000100000000
	basePoint := []uint64{
		r.xyz[0], r.xyz[1],r.xyz[2],r.xyz[3],
		r.xyz[4],r.xyz[5],r.xyz[6],r.xyz[7],
		r.xyz[8],r.xyz[9],r.xyz[10],r.xyz[11],
	}
	t1 := make([]uint64, 12)
	t2 := make([]uint64, 12)
	copy(t2, basePoint)

	zInv := make([]uint64, 4)
	zInvSq := make([]uint64, 4)
	for j := 0; j < 64; j++ {
		copy(t1, t2)
		for i := 0; i < 37; i++ {
			// The window size is 7 so we need to double 7 times.
			if i != 0 {
				for k := 0; k < 7; k++ {
					sm2p256PointDoubleAsm(t1, t1)
				}
			}
			// Convert the point to affine form. (Its values are
			// still in Montgomery form however.)
			p256Inverse(zInv, t1[8:12])
			sm2p256Sqr(zInvSq, zInv)
			sm2p256Mul(zInv, zInv, zInvSq)

			sm2p256Mul(t1[:4], t1[:4], zInvSq)
			sm2p256Mul(t1[4:8], t1[4:8], zInv)

			copy(t1[8:12], basePoint[8:12])
			// Update the table entry
			copy(Precomputed[i][j*8:], t1[:8])
		}
		if j == 0 {
			sm2p256PointDoubleAsm(t2, basePoint)
		} else {
			sm2p256PointAddAsm(t2, t2, basePoint)
		}
	}
	return
}

//fast sm2p256Mult with public key table
func (p *p256Point) p256PreMult(Precomputed *PCom, scalar []uint64) {
	wvalue := (scalar[0] << 1) & 0xff
	sel, sign := boothW7(uint(wvalue))
	sm2p256SelectBase(p.xyz[0:8], Precomputed[0][0:], sel)
	sm2p256NegCond(p.xyz[4:8], sign)

	// (This is one, in the Montgomery domain.)
	//p.xyz[8] = 0x0000000000000001
	//p.xyz[9] = 0xffffffff00000000
	//p.xyz[10] = 0xffffffffffffffff
	//p.xyz[11] = 0x00000000fffffffe
	p.xyz[8] = 0x0000000000000001
	p.xyz[9] = 0x00000000FFFFFFFF
	p.xyz[10] = 0x0000000000000000
	p.xyz[11] = 0x0000000100000000
	var t0 p256Point
	// (This is one, in the Montgomery domain.)
	//t0.xyz[8] = 0x0000000000000001
	//t0.xyz[9] = 0xffffffff00000000
	//t0.xyz[10] = 0xffffffffffffffff
	//t0.xyz[11] = 0x00000000fffffffe
	t0.xyz[8] = 0x0000000000000001
	t0.xyz[9] = 0x00000000FFFFFFFF
	t0.xyz[10] = 0x0000000000000000
	t0.xyz[11] = 0x0000000100000000
	index := uint(6)
	zero := sel

	for i := 1; i < 37; i++ {
		if index < 192 {
			wvalue = ((scalar[index/64] >> (index % 64)) + (scalar[index/64+1] << (64 - (index % 64)))) & 0xff
		} else {
			wvalue = (scalar[index/64] >> (index % 64)) & 0xff
		}
		index += 7
		sel, sign = boothW7(uint(wvalue))
		sm2p256SelectBase(t0.xyz[0:8], Precomputed[i][0:], sel)
		sm2p256PointAddAffineAsm(p.xyz[0:12], p.xyz[0:12], t0.xyz[0:8], sign, sel, zero)
		zero |= sel
	}
}

// todo  新增修改原SM2
func GenerateKey(random io.Reader) (*PrivateKey, error) {
	c := P256Sm2()
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(random, b)
	if err != nil {
		return nil, err
	}

	k := new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, two)
	k.Mod(k, n)
	k.Add(k, one)
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	priv.DInv = new(big.Int).Add(k, one)
	priv.DInv.ModInverse(priv.DInv, c.Params().N)
	// 如果对象c实现了optMethod则执行InitPubKeyTable方法
	if _, ok := c.(optMethod); ok {
		//fmt.Printf("GenerateKey opt.InitPubKeyTable====X:%x, Y:%x\n", priv.PublicKey.X, priv.PublicKey.Y)
		priv.PreComputed = InitPubKeyTable(priv.PublicKey.X, priv.PublicKey.Y)
		key := hexutils.BytesToHex(append(priv.PublicKey.X.Bytes(), priv.PublicKey.Y.Bytes()...))
		PreComputedCached.Add(key, priv.PreComputed)
	}

	return priv, nil
}

var generateRandK = _generateRandK
func _generateRandK(rand io.Reader, c elliptic.Curve) (k *big.Int) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err := io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}


func (curve sm2P256Curve) PreScalarMult(Precomputed *PCom, scalar []byte) (x,y *big.Int) {
	scalarReversed := make([]uint64, 4)
	p256GetScalar(scalarReversed, scalar)

	r := new(p256Point)
	r.p256PreMult(Precomputed,scalarReversed)
	x,y = r.p256PointToAffine()
	return
}
func (curve sm2P256Curve) CombinedMult(Precomputed *PCom, baseScalar, scalar []byte) (x, y *big.Int) {
	scalarReversed := make([]uint64, 4)
	var r1 p256Point
	r2 := new(p256Point)
	p256GetScalar(scalarReversed, baseScalar)
	r1IsInfinity := scalarIsZero(scalarReversed)
	r1.p256BaseMult(scalarReversed)

	p256GetScalar(scalarReversed, scalar)
	r2IsInfinity := scalarIsZero(scalarReversed)
	//fromBig(r2.xyz[0:4], maybeReduceModP(bigX))
	//fromBig(r2.xyz[4:8], maybeReduceModP(bigY))
	//sm2p256Mul(r2.xyz[0:4], r2.xyz[0:4], rr[:])
	//sm2p256Mul(r2.xyz[4:8], r2.xyz[4:8], rr[:])
	//
	//// This sets r2's Z value to 1, in the Montgomery domain.
	////	r2.xyz[8] = 0x0000000000000001
	////	r2.xyz[9] = 0xffffffff00000000
	////	r2.xyz[10] = 0xffffffffffffffff
	////	r2.xyz[11] = 0x00000000fffffffe
	//r2.xyz[8] = 0x0000000000000001
	//r2.xyz[9] = 0x00000000FFFFFFFF
	//r2.xyz[10] = 0x0000000000000000
	//r2.xyz[11] = 0x0000000100000000
	//
	////r2.p256ScalarMult(scalarReversed)
	////sm2p256PointAddAsm(r1.xyz[:], r1.xyz[:], r2.xyz[:])

	//r2.p256ScalarMult(scalarReversed)
	r2.p256PreMult(Precomputed,scalarReversed)

	var sum, double p256Point
	pointsEqual := sm2p256PointAddAsm(sum.xyz[:], r1.xyz[:], r2.xyz[:])
	sm2p256PointDoubleAsm(double.xyz[:], r1.xyz[:])
	sum.CopyConditional(&double, pointsEqual)
	sum.CopyConditional(&r1, r2IsInfinity)
	sum.CopyConditional(r2, r1IsInfinity)
	return sum.p256PointToAffine()
}

var PreComputedCached *lru.Cache
type PCom [37][64 * 8]uint64 // 18944 = 18.5k
func init() {
	PreComputedCached, _ = lru.New(len(PCom{})*1024) // 18.50MB
}

type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
	PreComputed *PCom //preComputation
}

type PrivateKey struct {
	PublicKey
	D *big.Int
	DInv *big.Int //(1+d)^-1
}
type optMethod interface {
	// CombinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
	CombinedMult(Precomputed *PCom, baseScalar, scalar []byte) (x, y *big.Int)
	// InitPubKeyTable implements precomputed table of public key
	//InitPubKeyTable(x, y *big.Int) (Precomputed *[37][64 * 8]uint64)
	// PreScalarMult implements fast multiplication of public key
	PreScalarMult(Precomputed *PCom, scalar []byte) (x, y *big.Int)
}

func Sm2Sign(priv *PrivateKey, msg, uid []byte, random io.Reader) (r, s *big.Int, err error) {
	var one = new(big.Int).SetInt64(1)
	//if len(hash) < 32 {
	//	err = errors.New("The length of hash has short than what SM2 need.")
	//	return
	//}

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(&priv.PublicKey))
	copy(m[32:], msg)

	hash := sm3.Sm3Sum(m)
	e := new(big.Int).SetBytes(hash[:])
	k := generateRandK(random, priv.PublicKey.Curve)

	x1, _ := priv.PublicKey.Curve.ScalarBaseMult(k.Bytes())

	n := priv.PublicKey.Curve.Params().N

	r = new(big.Int).Add(e, x1)

	r.Mod(r, n)

	s1 := new(big.Int).Mul(r, priv.D)
	s1.Sub(k, s1)

	s2 := new(big.Int)
	if priv.DInv == nil {
		s2 = s2.Add(one, priv.D)
		s2.ModInverse(s2, n)
	} else {
		s2 = priv.DInv
	}

	s = new(big.Int).Mul(s1, s2)
	s.Mod(s, n)
	//digest, err := priv.PublicKey.Sm3Digest(msg, uid)
	//if err != nil {
	//	return nil, nil, err
	//}
	//e := new(big.Int).SetBytes(digest)
	//c := priv.PublicKey.Curve
	//N := c.Params().N
	//if N.Sign() == 0 {
	//	return nil, nil, errZeroParam
	//}
	//var k *big.Int
	//for { // 调整算法细节以实现SM2
	//	for {
	//		k, err = randFieldElement(c, random)
	//		if err != nil {
	//			r = nil
	//			return
	//		}
	//		r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
	//		r.Add(r, e)
	//		r.Mod(r, N)
	//		if r.Sign() != 0 {
	//			if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
	//				break
	//			}
	//		}
	//
	//	}
	//	rD := new(big.Int).Mul(priv.D, r)
	//	s = new(big.Int).Sub(k, rD)
	//	d1 := new(big.Int).Add(priv.D, one)
	//	d1Inv := new(big.Int).ModInverse(d1, N)
	//	s.Mul(s, d1Inv)
	//	s.Mod(s, N)
	//	if s.Sign() != 0 {
	//		break
	//	}
	//}
	return
}
func Sm2Verify(pub *PublicKey, msg, uid []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N
	one := new(big.Int).SetInt64(1)
	if r.Cmp(one) < 0 || s.Cmp(one) < 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}
	if len(uid) == 0 {
		uid = default_uid
	}
	za, err := ZA(pub, uid)
	if err != nil {
		return false
	}
	e, err := msgHash(za, msg)
	if err != nil {
		return false
	}
	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}
	var x *big.Int
	key := hexutils.BytesToHex(append(pub.X.Bytes(), pub.Y.Bytes()...))
	opt, _ := c.(optMethod)
	if pub.PreComputed != nil {
		x, _ = opt.CombinedMult(pub.PreComputed, s.Bytes(), t.Bytes())
	} else {
		// 由于交易的公钥是临时恢复的,所以验签会直接执行以下流程
		if val, ok := PreComputedCached.Get(key); ok {
			pub.PreComputed = val.(*PCom)
			x, _ = opt.CombinedMult(pub.PreComputed, s.Bytes(), t.Bytes())
		} else {
			pub.PreComputed = InitPubKeyTable(pub.X, pub.Y)
			// 缓存计算过程
			PreComputedCached.Add(key, pub.PreComputed)
			x, _ = opt.CombinedMult(pub.PreComputed, s.Bytes(), t.Bytes())
		}
	}
	x1 := new(big.Int).Add(e, x)
	x1 = x1.Mod(x1, N)
	return  x1.Cmp(r)==0
}
/*
    za, err := ZA(pub, uid)
	if err != nil {
		return
	}
	e, err := msgHash(za, msg)
	hash=e.getBytes()
*/
func Verify(pub *PublicKey, msg []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	n := c.Params().N

	var m = make([]byte, 32+len(msg))
	copy(m, getZ(pub))
	copy(m[32:], msg)
	//h := sm3.New()
	//hash := h.Sum(m)
	hash := sm3.Sm3Sum(m)
	e := new(big.Int).SetBytes(hash[:])

	t := new(big.Int).Add(r, s)

	// Check if implements S1*g + S2*p
	//Using fast multiplication CombinedMult.
	var x1 *big.Int
	key := hexutils.BytesToHex(append(pub.X.Bytes(), pub.Y.Bytes()...))
	opt, _ := c.(optMethod)
	if pub.PreComputed != nil {
		x1, _ = opt.CombinedMult(pub.PreComputed, s.Bytes(), t.Bytes())
	} else {
		// 由于交易的公钥是临时恢复的,所以验签会直接执行以下流程
		if val, ok := PreComputedCached.Get(key); ok {
			pub.PreComputed = val.(*PCom)
			x1, _ = opt.CombinedMult(pub.PreComputed, s.Bytes(), t.Bytes())
		} else {
			pub.PreComputed = InitPubKeyTable(pub.X, pub.Y)
			// 缓存计算过程
			PreComputedCached.Add(key, pub.PreComputed)
			x1, _ = opt.CombinedMult(pub.PreComputed, s.Bytes(), t.Bytes())
		}
	}


	x := new(big.Int).Add(e, x1)
	x = x.Mod(x, n)

	return x.Cmp(r) == 0
}