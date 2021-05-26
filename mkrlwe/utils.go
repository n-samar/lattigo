package mkrlwe

import (
	"sort"

	"github.com/ldsec/lattigo/v2/bfv"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

// Dot computes the dot product of two decomposed polynomials in ring^d and store the result in res
func Dot(p1 *MKDecomposedPoly, p2 *MKDecomposedPoly, r *ring.Ring) *ring.Poly {
	if len(p1.Poly) != len(p2.Poly) {
		panic("Cannot compute dot product on vectors of different size !")
	}

	res := r.NewPoly()

	for i := uint64(0); i < uint64(len(p1.Poly)); i++ {

		r.MulCoeffsMontgomeryAndAdd(p1.Poly[i], p2.Poly[i], res)
	}

	return res
}

// DotLvl computes the dot product of two decomposed polynomials in ringQ^d up to q_level and store the result in res
func DotLvl(level uint64, p1 *MKDecomposedPoly, p2 *MKDecomposedPoly, r *ring.Ring) *ring.Poly {
	if len(p1.Poly) != len(p2.Poly) {
		panic("Cannot compute dot product on vectors of different size !")
	}

	res := r.NewPoly()

	for i := uint64(0); i < uint64(len(p1.Poly)); i++ {

		r.MulCoeffsMontgomeryAndAddLvl(level, p1.Poly[i], p2.Poly[i], res)
	}

	return res
}

// MergeSlices merges two slices of uint64 and places the result in s3
// the resulting slice is sorted in ascending order
func MergeSlices(s1, s2 []uint64) []uint64 {

	s3 := make([]uint64, len(s1))

	copy(s3, s1)

	for _, el := range s2 {

		if Contains(s3, el) < 0 {
			s3 = append(s3, el)
		}
	}

	sort.Slice(s3, func(i, j int) bool { return s3[i] < s3[j] })

	return s3
}

// Contains return the element's index if the element is in the slice. -1 otherwise
func Contains(s []uint64, e uint64) int {

	for i, el := range s {
		if el == e {
			return i
		}
	}
	return -1
}

// GetRandomPoly samples a polynomial with a uniform distribution in the given ring
func GetRandomPoly(params *rlwe.Parameters, r *ring.Ring) *ring.Poly {

	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	return GetUniformSampler(params, r, prng).ReadNew()
}

// EqualsSlice returns true if both slices are equal
func EqualsSlice(s1, s2 []uint64) bool {

	if len(s1) != len(s2) {
		return false
	}

	for i, e := range s1 {
		if e != s2[i] {
			return false
		}
	}

	return true
}

// EqualsPoly returns true if both polynomials are equal
func EqualsPoly(p1 *ring.Poly, p2 *ring.Poly) bool {

	if len(p1.Coeffs) != len(p2.Coeffs) {
		return false
	}

	for i, e := range p1.Coeffs {

		if !EqualsSlice(e, p2.Coeffs[i]) {
			return false
		}
	}

	return true
}

// MinLevelWithNil returns the smallest level of the elements, taking into account that they can be nil, and 0 if they are all nil
func MinLevelWithNil(el0, el1, elOut *ckks.Element) uint64 {
	level := uint64(0)

	if el0 == nil && el1 == nil && elOut != nil {
		level = elOut.Level()
	}

	if el0 == nil && el1 != nil && elOut == nil {
		level = el1.Level()
	}

	if el0 == nil && el1 != nil && elOut != nil {
		level = utils.MinUint64(el1.Level(), elOut.Level())
	}

	if el0 != nil && el1 == nil && elOut == nil {
		level = el0.Level()
	}

	if el0 != nil && el1 == nil && elOut != nil {
		level = utils.MinUint64(el0.Level(), elOut.Level())
	}

	if el0 != nil && el1 != nil && elOut == nil {
		level = utils.MinUint64(el0.Level(), el1.Level())
	}
	return level
}

// GetThreeElementsckksWithNil gets the elements of ckks operands and takes nil into account
func GetThreeElementsckksWithNil(op0, op1, opOut ckks.Operand) (el0, el1, elOut *ckks.Element) {

	if op0 == nil && op1 == nil && opOut == nil {
		el0, el1, elOut = nil, nil, nil
	}
	if op0 == nil && op1 == nil && opOut != nil {
		el0, el1, elOut = nil, nil, opOut.El()
	}
	if op0 == nil && op1 != nil && opOut == nil {
		el0, el1, elOut = nil, op1.El(), nil
	}
	if op0 == nil && op1 != nil && opOut != nil {
		el0, el1, elOut = nil, op1.El(), opOut.El()
	}

	if op0 != nil && op1 == nil && opOut == nil {
		el0, el1, elOut = op0.El(), nil, nil
	}

	if op0 != nil && op1 == nil && opOut != nil {
		el0, el1, elOut = op0.El(), nil, opOut.El()
	}

	if op0 != nil && op1 != nil && opOut == nil {
		el0, el1, elOut = op0.El(), op1.El(), nil
	} else {
		el0, el1, elOut = op0.El(), op1.El(), opOut.El()
	}
	return
}

// GetThreeElementsbfvWithNil gets the elements of ckks operands and takes nil into account
func GetThreeElementsbfvWithNil(op0, op1, opOut bfv.Operand) (el0, el1, elOut *rlwe.Element) {

	if op0 == nil && op1 == nil && opOut == nil {
		el0, el1, elOut = nil, nil, nil
	}
	if op0 == nil && op1 == nil && opOut != nil {
		el0, el1, elOut = nil, nil, opOut.El()
	}
	if op0 == nil && op1 != nil && opOut == nil {
		el0, el1, elOut = nil, op1.El(), nil
	}
	if op0 == nil && op1 != nil && opOut != nil {
		el0, el1, elOut = nil, op1.El(), opOut.El()
	}

	if op0 != nil && op1 == nil && opOut == nil {
		el0, el1, elOut = op0.El(), nil, nil
	}

	if op0 != nil && op1 == nil && opOut != nil {
		el0, el1, elOut = op0.El(), nil, opOut.El()
	}

	if op0 != nil && op1 != nil && opOut == nil {
		el0, el1, elOut = op0.El(), op1.El(), nil
	} else {
		el0, el1, elOut = op0.El(), op1.El(), opOut.El()
	}
	return
}