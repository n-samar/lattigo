// Package bfv implements a RNS-accelerated BGV homomorphic encryption scheme. It provides modular arithmetic over the integers.
package bgv

import (
	"math/big"

	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/utils"
)

const GaloisGen uint64 = 5

type Encoder interface {
	Encode(coeffs interface{}, pt *Plaintext)
	EncodeNew(coeffs interface{}, level int, scale uint64) (pt *Plaintext)

	DecodeUint(pt *Plaintext, coeffs []uint64)
	DecodeInt(pt *Plaintext, coeffs []int64)
	DecodeUintNew(pt *Plaintext) (coeffs []uint64)
	DecodeIntNew(pt *Plaintext) (coeffs []int64)

	ShallowCopy() Encoder
}

// encoder is a structure that stores the parameters to encode values on a plaintext in a SIMD (Single-Instruction Multiple-Data) fashion.
type encoder struct {
	params Parameters

	indexMatrix []uint64

	buffQ *ring.Poly
	buffT *ring.Poly

	paramsQP []ring.ModupParams
	qHalf    []*big.Int
}

// NewEncoder creates a new encoder from the provided parameters.
func NewEncoder(params Parameters) Encoder {

	var N, logN, pow, pos uint64 = uint64(params.N()), uint64(params.LogN()), 1, 0

	mask := 2*N - 1

	indexMatrix := make([]uint64, N)

	for i, j := 0, int(N>>1); i < int(N>>1); i, j = i+1, j+1 {

		pos = utils.BitReverse64(pow>>1, logN)

		indexMatrix[i] = pos
		indexMatrix[j] = N - pos - 1

		pow *= GaloisGen
		pow &= mask
	}

	ringQ := params.RingQ()
	ringT := params.RingT()

	paramsQP := make([]ring.ModupParams, len(ringQ.Modulus))

	qHalf := make([]*big.Int, len(ringQ.Modulus))

	for i := 1; i < len(ringQ.Modulus); i++ {

		paramsQP[i] = ring.GenModUpParams(ringQ.Modulus[:i+1], ringT.Modulus)

		qHalf[i] = new(big.Int).Set(ringQ.ModulusAtLevel[i])
		qHalf[i].Rsh(qHalf[i], 1)
	}

	return &encoder{
		params:      params,
		indexMatrix: indexMatrix,
		buffQ:       ringQ.NewPoly(),
		buffT:       ringT.NewPoly(),
		paramsQP:    paramsQP,
		qHalf:       qHalf,
	}
}

// EncodeNew encodes a slice of integers of type []uint64 or []int64 of size at most N on a newly allocated plaintext.
func (ecd *encoder) EncodeNew(values interface{}, level int, scale uint64) (pt *Plaintext) {
	pt = NewPlaintext(ecd.params, level, scale)
	ecd.Encode(values, pt)
	return
}

// Encode encodes a slice of integers of type []uint64 or []int64 of size at most N into a pre-allocated plaintext.
func (ecd *encoder) Encode(values interface{}, pt *Plaintext) {
	ecd.encodeRingT(values, ecd.buffT)
	ecd.ringT2Q(pt.Level(), pt.Scale, ecd.buffT, pt.Value)
	ecd.params.RingQ().NTTLvl(pt.Level(), pt.Value, pt.Value)
}

func (ecd *encoder) encodeRingT(values interface{}, pT *ring.Poly) {

	if len(pT.Coeffs[0]) != len(ecd.indexMatrix) {
		panic("cannot EncodeRingT: invalid plaintext to receive encoding: number of coefficients does not match the ring degree")
	}

	pt := pT.Coeffs[0]

	ringT := ecd.params.RingT()

	var valLen int
	switch values := values.(type) {
	case []uint64:
		for i, c := range values {
			pt[ecd.indexMatrix[i]] = c
		}
		ringT.Reduce(pT, pT)
		valLen = len(values)
	case []int64:

		T := ringT.Modulus[0]
		bredparamsT := ringT.BredParams[0]

		var sign, abs uint64
		for i, c := range values {
			sign = uint64(c) >> 63
			abs = ring.BRedAdd(uint64(c*((int64(sign)^1)-int64(sign))), T, bredparamsT)
			pt[ecd.indexMatrix[i]] = sign*(T-abs) | (sign^1)*abs
		}
		valLen = len(values)
	default:
		panic("cannot EncodeRingT: coeffs must be either []uint64 or []int64")
	}

	for i := valLen; i < len(ecd.indexMatrix); i++ {
		pt[ecd.indexMatrix[i]] = 0
	}

	ringT.InvNTT(pT, pT)
}

func (ecd *encoder) ringT2Q(level int, scale uint64, pT, pQ *ring.Poly) {

	ecd.params.RingT().MulScalar(pT, scale, pQ)

	for i := 1; i < level+1; i++ {
		copy(pQ.Coeffs[i], pQ.Coeffs[0])
	}
}

func (ecd *encoder) ringQ2T(level int, scale uint64, pQ, pT *ring.Poly) {

	ringQ := ecd.params.RingQ()
	ringT := ecd.params.RingT()

	if level > 0 {
		ringQ.AddScalarBigintLvl(level, ecd.buffQ, ecd.qHalf[level], ecd.buffQ)
		ring.ModUpExact(pQ.Coeffs[:level+1], pT.Coeffs, ringQ, ringT, ecd.paramsQP[level])
		ringT.SubScalarBigint(pT, ecd.qHalf[level], pT)
	} else {
		ringQ.AddScalarLvl(level, ecd.buffQ, ringQ.Modulus[0]>>1, ecd.buffQ)
		ringT.Reduce(ecd.buffQ, pT)
		ringT.SubScalar(pT, (ringQ.Modulus[0]>>1)%ringT.Modulus[0], pT)
	}

	ringT.MulScalar(ecd.buffT, ring.ModExp(scale, ringT.Modulus[0]-2, ringT.Modulus[0]), ecd.buffT)
}

// DecodeUint decodes a any plaintext type and write the coefficients in coeffs. It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) DecodeUint(pt *Plaintext, coeffs []uint64) {

	ecd.params.RingQ().InvNTTLvl(pt.Level(), pt.Value, ecd.buffQ)
	ecd.ringQ2T(pt.Level(), pt.Scale, ecd.buffQ, ecd.buffT)
	ecd.params.RingT().NTT(ecd.buffT, ecd.buffT)

	for i := 0; i < ecd.params.RingQ().N; i++ {
		coeffs[i] = ecd.buffT.Coeffs[0][ecd.indexMatrix[i]]
	}
}

// DecodeUintNew decodes any plaintext type and returns the coefficients in a new []uint64.
// It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) DecodeUintNew(pt *Plaintext) (coeffs []uint64) {
	coeffs = make([]uint64, ecd.params.RingQ().N)
	ecd.DecodeUint(pt, coeffs)
	return
}

// DecodeInt decodes a any plaintext type and writes the coefficients in coeffs. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) DecodeInt(pt *Plaintext, coeffs []int64) {

	ecd.params.RingQ().InvNTTLvl(pt.Level(), pt.Value, ecd.buffQ)
	ecd.ringQ2T(pt.Level(), pt.Scale, ecd.buffQ, ecd.buffT)
	ecd.params.RingT().NTT(ecd.buffT, ecd.buffT)

	modulus := int64(ecd.params.T())
	modulusHalf := modulus >> 1
	var value int64
	for i := 0; i < ecd.params.RingQ().N; i++ {
		value = int64(ecd.buffT.Coeffs[0][ecd.indexMatrix[i]])
		coeffs[i] = value
		if value >= modulusHalf {
			coeffs[i] -= modulus
		}
	}
}

// DecodeIntNew decodes any plaintext type and returns the coefficients in a new []int64. It also decodes the sign
// modulus (by centering the values around the plaintext). It panics if p is not PlaintextRingT, Plaintext or PlaintextMul.
func (ecd *encoder) DecodeIntNew(pt *Plaintext) (coeffs []int64) {
	coeffs = make([]int64, ecd.params.RingQ().N)
	ecd.DecodeInt(pt, coeffs)
	return
}

// ShallowCopy creates a shallow copy of Encoder in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Encoder can be used concurrently.
func (ecd *encoder) ShallowCopy() Encoder {
	return &encoder{
		params:      ecd.params,
		indexMatrix: ecd.indexMatrix,
		buffQ:       ecd.params.RingQ().NewPoly(),
		buffT:       ecd.params.RingT().NewPoly(),
		paramsQP:    ecd.paramsQP,
	}
}
