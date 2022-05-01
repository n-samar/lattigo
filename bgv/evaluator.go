package bgv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

// Operand is a common interface for Ciphertext and Plaintext.
type Operand interface {
	El() *rlwe.Ciphertext
	Level() int
	Degree() int
}

// Evaluator is an interface implementing the public methodes of the eval.
type Evaluator interface {
	Rescale(ctIn, ctOut *Ciphertext) (err error)
	ShallowCopy() Evaluator
	WithKey(rlwe.EvaluationKey) Evaluator
}

// evaluator is a struct that holds the necessary elements to perform the homomorphic operations between ciphertexts and/or plaintexts.
// It also holds a memory buffer used to store intermediate computations.
type evaluator struct {
	*evaluatorBase
	*evaluatorBuffers
	*rlwe.Evaluator
}

type evaluatorBase struct {
	params       Parameters
	qiInvModTNeg []uint64
	qLModqi      [][]uint64
}

func newEvaluatorPrecomp(params Parameters) *evaluatorBase {
	ringQ := params.RingQ()
	ringT := params.RingT()
	t := params.T()

	qiInvModTNeg := make([]uint64, len(ringQ.Modulus))

	for i, qi := range ringQ.Modulus {
		qiInvModTNeg[i] = ring.MForm(t-ring.ModExp(qi, t-2, t), t, ringT.BredParams[0])
	}

	qLModqi := make([][]uint64, len(ringQ.Modulus)-1)

	for j := len(ringQ.Modulus) - 1; j > 0; j-- {
		qLModqi[j-1] = make([]uint64, j)
		for i := 0; i < j; i++ {
			qLModqi[j-1][i] = ring.MForm(ringQ.Modulus[j], ringQ.Modulus[i], ringQ.BredParams[i])
		}
	}

	return &evaluatorBase{
		params:       params,
		qiInvModTNeg: qiInvModTNeg,
		qLModqi:      qLModqi,
	}
}

type evaluatorBuffers struct {
}

func newEvaluatorBuffer(eval *evaluatorBase) *evaluatorBuffers {
	evb := new(evaluatorBuffers)
	return evb
}

// NewEvaluator creates a new Evaluator, that can be used to do homomorphic
// operations on ciphertexts and/or plaintexts. It stores a memory buffer
// and ciphertexts that will be used for intermediate values.
func NewEvaluator(params Parameters, evaluationKey rlwe.EvaluationKey) Evaluator {
	ev := new(evaluator)
	ev.evaluatorBase = newEvaluatorPrecomp(params)
	ev.evaluatorBuffers = newEvaluatorBuffer(ev.evaluatorBase)
	ev.Evaluator = rlwe.NewEvaluator(params.Parameters, &evaluationKey)

	return ev
}

// ShallowCopy creates a shallow copy of this evaluator in which the read-only data-structures are
// shared with the receiver.
func (eval *evaluator) ShallowCopy() Evaluator {
	return &evaluator{
		evaluatorBase:    eval.evaluatorBase,
		Evaluator:        eval.Evaluator.ShallowCopy(),
		evaluatorBuffers: newEvaluatorBuffer(eval.evaluatorBase),
	}
}

// WithKey creates a shallow copy of this evaluator in which the read-only data-structures are
// shared with the receiver but the EvaluationKey is evaluationKey.
func (eval *evaluator) WithKey(evaluationKey rlwe.EvaluationKey) Evaluator {
	return &evaluator{
		evaluatorBase:    eval.evaluatorBase,
		Evaluator:        eval.Evaluator.WithKey(&evaluationKey),
		evaluatorBuffers: eval.evaluatorBuffers,
	}
}

func (eval *evaluator) Rescale(ctIn, ctOut *Ciphertext) (err error) {

	if ctIn.Level() == 0 {
		return fmt.Errorf("cannot rescale: ctIn already at level 0")
	}

	if ctOut.Level() < ctIn.Level()-1 {
		return fmt.Errorf("cannot rescale: ctOut.Level() < ctIn.Level()-1")
	}

	level := ctIn.Level()
	ringQ := eval.params.RingQ()
	ringT := eval.params.RingT()

	buff0 := eval.BuffQP[0].Q.Coeffs[0]
	buff1 := eval.BuffQP[1].Q.Coeffs[0]
	buff2 := eval.BuffQP[2].Q.Coeffs[0]

	for i, el := range ctIn.Value {

		// buff0 = coeffs[level]
		ringQ.InvNTTSingleLazy(level, el.Coeffs[level], buff0)

		// buff1 = (buff0 * qL^-1) % t
		ring.MulScalarMontgomeryVec(buff0, buff1, eval.qiInvModTNeg[level], ringT.Modulus[0], ringT.MredParams[0])

		for j := 0; j < level; j++ {

			qi := ringQ.Modulus[j]
			qLModqi := eval.qLModqi[level-1][j]
			mredParams := ringQ.MredParams[j]
			cIn := el.Coeffs[j]
			cOut := ctOut.Value[i].Coeffs[j]

			// buff2 = (buff1 * qL) % qi
			ring.MulScalarMontgomeryVec(buff1, buff2, qLModqi, qi, mredParams)

			// buff2 = buff2 + buff0
			ring.AddVecNoMod(buff2, buff0, buff2)

			ringQ.NTTSingleLazy(j, buff2, buff2)

			// cOut = ((buff2 + 2*qi - cIn) * -qL^-1) % qi
			ring.SubVecAndMulScalarMontgomeryTwoQiVec(buff2, cIn, cOut, ringQ.RescaleParams[level-1][j], qi, mredParams)

		}

		ctOut.Value[i].Coeffs = ctOut.Value[i].Coeffs[:level]
	}

	ctOut.Scale = ring.BRed(ctOut.Scale, ringQ.Modulus[level], ringT.Modulus[0], ringT.BredParams[0])

	return
}
