package ckks

import (
	"fmt"

	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

// DomainSwitcher is a type for switching between the standard CKKS domain (which encrypts vectors of complex numbers)
// and the conjugate invariant variant of CKKS (which encrypts vectors of real numbers).
type DomainSwitcher struct {
	stdRingQ, conjugateRingQ *ring.Ring

	*SwkComplexToReal
	*SwkRealToComplex

	permuteNTTIndex []uint64
}

// NewDomainSwitcher instantiate a new DomainSwitcher type. It may be instantiated from parameters from either RingType.
// The method returns an error if the parameters cannot support the switching (e.g., the NTTs are undefined for
// either of the two ring types).
func NewDomainSwitcher(params Parameters, comlexToRealSwk *SwkComplexToReal, RealToComplexSwk *SwkRealToComplex) (DomainSwitcher, error) {

	s := DomainSwitcher{
		SwkComplexToReal: comlexToRealSwk,
		SwkRealToComplex: RealToComplexSwk,
	}
	var err error
	if s.stdRingQ, err = params.RingQ().StandardRing(); err != nil {
		return DomainSwitcher{}, fmt.Errorf("cannot switch between schemes because the standard NTT is undefined for params: %f", err)
	}
	if s.conjugateRingQ, err = params.RingQ().ConjugateInvariantRing(); err != nil {
		return DomainSwitcher{}, fmt.Errorf("cannot switch between schemes because the standard NTT is undefined for params: %f", err)
	}

	s.permuteNTTIndex = s.stdRingQ.PermuteNTTIndex(s.stdRingQ.NthRoot - 1)
	return s, nil
}

// ComplexToReal switches the provided ciphertext `ctIn` from the standard domain to the conjugate
// invariant domain and writes the result into `ctOut`.
// Given ctInCKKS = enc(real(m) + imag(m)) in Z[X](X^N + 1), returns ctOutCI = enc(real(m))
// in Z[X+X^-1]/(X^N + 1) in compressed form (N/2 coefficients).
// The scale of the output ciphertext is twice the scale of the input one.
// Requires the ring degree of ctOut to be half the ring degree of ctIn.
// The security is changed from Z[X]/(X^N+1) to Z[X]/(X^N/2+1).
// The method panics if the DomainSwitcher was not initialized with a SwkComplexToReal key.
func (switcher *DomainSwitcher) ComplexToReal(eval *rlwe.Evaluator, ctIn, ctOut *Ciphertext) {

	if eval.Parameters().RingType() != ring.Standard {
		panic("cannot ComplexToReal: provided evaluator is not instantiated with RingType ring.Standard")
	}

	level := utils.MinInt(ctIn.Level(), ctOut.Level())

	if len(ctIn.Value[0].Coeffs[0]) != 2*len(ctOut.Value[0].Coeffs[0]) {
		panic("cannot ComplexToReal: ctIn ring degree must be twice ctOut ring degree")
	}

	if switcher.SwkComplexToReal == nil {
		panic("cannot ComplexToReal: no SwkComplexToReal provided to this DomainSwitcher")
	}

	eval.GadgetProduct(level, ctIn.Value[1], switcher.SwkComplexToReal.GadgetCiphertext, eval.BuffQP[1].Q, eval.BuffQP[2].Q)
	switcher.stdRingQ.AddLvl(level, eval.BuffQP[1].Q, ctIn.Value[0], eval.BuffQP[1].Q)

	switcher.conjugateRingQ.FoldStandardToConjugateInvariant(level, eval.BuffQP[1].Q, switcher.permuteNTTIndex, ctOut.Value[0])
	switcher.conjugateRingQ.FoldStandardToConjugateInvariant(level, eval.BuffQP[2].Q, switcher.permuteNTTIndex, ctOut.Value[1])
	ctOut.scale = 2 * ctIn.scale
}

// RealToComplex switches the provided ciphertext `ctIn` from the conjugate invariant domain to the
// standard domain and writes the result into `ctOut`.
// Given ctInCI = enc(real(m)) in Z[X+X^-1]/(X^2N+1) in compressed form (N coefficients), returns
// ctOutCKKS = enc(real(m) + imag(0)) in Z[X]/(X^2N+1).
// Requires the ring degree of ctOut to be twice the ring degree of ctIn.
// The security is changed from Z[X]/(X^N+1) to Z[X]/(X^2N+1).
// The method panics if the DomainSwitcher was not initialized with a SwkRealToComplex key.
func (switcher *DomainSwitcher) RealToComplex(eval *rlwe.Evaluator, ctIn, ctOut *Ciphertext) {

	if eval.Parameters().RingType() != ring.Standard {
		panic("cannot RealToComplex: provided evaluator is not instantiated with RingType ring.Standard")
	}

	level := utils.MinInt(ctIn.Level(), ctOut.Level())

	if 2*len(ctIn.Value[0].Coeffs[0]) != len(ctOut.Value[0].Coeffs[0]) {
		panic("cannot RealToComplex: ctOut ring degree must be twice ctIn ring degree")
	}

	if switcher.SwkRealToComplex == nil {
		panic("cannot RealToComplex: no SwkRealToComplex provided to this DomainSwitcher")
	}

	switcher.stdRingQ.UnfoldConjugateInvariantToStandard(level, ctIn.Value[0], ctOut.Value[0])
	switcher.stdRingQ.UnfoldConjugateInvariantToStandard(level, ctIn.Value[1], ctOut.Value[1])

	// Switches the RCKswitcher key [X+X^-1] to a CKswitcher key [X]
	eval.GadgetProduct(level, ctOut.Value[1], switcher.SwkRealToComplex.GadgetCiphertext, eval.BuffQP[1].Q, eval.BuffQP[2].Q)
	switcher.stdRingQ.AddLvl(level, ctOut.Value[0], eval.BuffQP[1].Q, ctOut.Value[0])
	ring.CopyValues(eval.BuffQP[2].Q, ctOut.Value[1])
}
