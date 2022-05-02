package bgv

import (
	"fmt"
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
	"math/big"
)

// Operand is a common interface for Ciphertext and Plaintext.
type Operand interface {
	El() *rlwe.Ciphertext
	Level() int
	Degree() int
	ScalingFactor() uint64
}

// Evaluator is an interface implementing the public methodes of the eval.
type Evaluator interface {
	Add(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext)
	AddNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext)
	Sub(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext)
	SubNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext)
	Neg(ctIn *Ciphertext, ctOut *Ciphertext)
	NegNew(ctIn *Ciphertext) (ctOut *Ciphertext)

	AddScalar(ctIn *Ciphertext, scalar uint64, ctOut *Ciphertext)
	AddScalarNew(ctIn *Ciphertext, scalar uint64) (ctOut *Ciphertext)
	MulScalar(ctIn *Ciphertext, scalar uint64, ctOut *Ciphertext)
	MulScalarNew(ctIn *Ciphertext, scalar uint64) (ctOut *Ciphertext)
	MulScalarAndAdd(ctIn *Ciphertext, scalar uint64, ctOut *Ciphertext)

	DropLevelNew(ct0 *Ciphertext, levels int) (ctOut *Ciphertext)
	DropLevel(ct0 *Ciphertext, levels int)

	MulNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext)
	Mul(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext)
	MulRelinNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext)
	MulRelin(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext)

	MulAndAdd(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext)
	MulRelinAndAdd(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext)

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
	tInvModQ     []*big.Int
}

func newEvaluatorPrecomp(params Parameters) *evaluatorBase {
	ringQ := params.RingQ()
	ringT := params.RingT()
	t := params.T()

	qiInvModTNeg := make([]uint64, len(ringQ.Modulus))
	tInvModQ := make([]*big.Int, len(ringQ.Modulus))

	for i, qi := range ringQ.Modulus {
		qiInvModTNeg[i] = ring.MForm(t-ring.ModExp(qi, t-2, t), t, ringT.BredParams[0])
		tInvModQ[i] = ring.NewUint(t)
		tInvModQ[i].ModInverse(tInvModQ[i], ringQ.ModulusAtLevel[i])
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
		tInvModQ:     tInvModQ,
	}
}

type evaluatorBuffers struct {
	buffQ [3]*ring.Poly
}

func newEvaluatorBuffer(eval *evaluatorBase) *evaluatorBuffers {
	ringQ := eval.params.RingQ()
	buffQ := [3]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly(), ringQ.NewPoly()}
	for i := range buffQ {
		buffQ[i].IsNTT = true
	}
	return &evaluatorBuffers{
		buffQ: buffQ,
	}
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

func (eval *evaluator) checkBinary(op0, op1, opOut Operand, opOutMinDegree int) {
	if op0 == nil || op1 == nil || opOut == nil {
		panic("operands cannot be nil")
	}

	if op0.Degree()+op1.Degree() == 0 {
		panic("operands cannot be both plaintext")
	}

	if opOut.Degree() < opOutMinDegree {
		panic("receiver operand degree is too small")
	}

	if op0.Degree() > 6 || op1.Degree() > 6 || opOut.Degree() > 6 {
		panic("operands degree cannot be larger than 6")
	}

	for _, pol := range op0.El().Value {
		if !pol.IsNTT {
			panic("cannot evaluate: op0 must be in NTT")
		}
	}

	for _, pol := range op1.El().Value {
		if !pol.IsNTT {
			panic("cannot evaluate: op1 must be in NTT")
		}
	}
}

func (eval *evaluator) evaluateInPlace(el0, el1, elOut *Ciphertext, evaluate func(int, *ring.Poly, *ring.Poly, *ring.Poly)) {

	smallest, largest, _ := rlwe.GetSmallestLargest(el0.El(), el1.El())

	level := utils.MinInt(utils.MinInt(el0.Level(), el1.Level()), elOut.Level())

	if elOut.Level() > level {
		for i := range elOut.Value {
			elOut.Value[i].Coeffs = elOut.Value[i].Coeffs[:level+1]
		}
	}

	for i := 0; i < smallest.Degree()+1; i++ {
		evaluate(level, el0.Value[i], el1.Value[i], elOut.Value[i])
	}

	// If the inputs degrees differ, it copies the remaining degree on the receiver.
	if largest != nil && largest != elOut.El() { // checks to avoid unnecessary work.
		for i := smallest.Degree() + 1; i < largest.Degree()+1; i++ {
			elOut.Value[i].Copy(largest.Value[i])
		}
	}

	elOut.Scale = el0.Scale
}

func (eval *evaluator) matchScaleThenEvaluateInPlace(el0, el1, elOut *Ciphertext, evaluate func(int, *ring.Poly, uint64, *ring.Poly)) {

	level := utils.MinInt(utils.MinInt(el0.Level(), el1.Level()), elOut.Level())

	r0, r1, _ := eval.matchScalesBinary(el0.Scale, el1.Scale)

	for i := range el0.Value {
		eval.params.RingQ().MulScalarLvl(level, el0.Value[i], r0, elOut.Value[i])
	}

	for i := range el1.Value {
		evaluate(level, el1.Value[i], r1, elOut.Value[i])
	}

	ringT := eval.params.RingT()
	elOut.Scale = ring.BRed(el0.Scale, r0, ringT.Modulus[0], ringT.BredParams[0])
}

func (eval *evaluator) newCiphertextBinary(op0, op1 Operand) (ctOut *Ciphertext) {
	return NewCiphertext(eval.params, utils.MaxInt(op0.Degree(), op1.Degree()), utils.MinInt(op0.Level(), op1.Level()), 1)
}

// Add adds op1 to ctIn and returns the result in ctOut.
func (eval *evaluator) Add(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	eval.checkBinary(ctIn, op1, ctOut, utils.MaxInt(ctIn.Degree(), op1.Degree()))

	if ctIn.Scale == op1.ScalingFactor() {
		eval.evaluateInPlace(ctIn, &Ciphertext{op1.El(), op1.ScalingFactor()}, ctOut, eval.params.RingQ().AddLvl)
	} else {
		eval.matchScaleThenEvaluateInPlace(ctIn, &Ciphertext{op1.El(), op1.ScalingFactor()}, ctOut, eval.params.RingQ().MulScalarAndAddLvl)
	}
}

func (eval *evaluator) AddNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	ctOut = eval.newCiphertextBinary(ctIn, op1)
	eval.Add(ctIn, op1, ctOut)
	return
}

func (eval *evaluator) Sub(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	eval.checkBinary(ctIn, op1, ctOut, utils.MaxInt(ctIn.Degree(), op1.Degree()))

	if ctIn.Scale == op1.ScalingFactor() {
		eval.evaluateInPlace(ctIn, &Ciphertext{op1.El(), op1.ScalingFactor()}, ctOut, eval.params.RingQ().SubLvl)
	} else {
		eval.matchScaleThenEvaluateInPlace(ctIn, &Ciphertext{op1.El(), op1.ScalingFactor()}, ctOut, eval.params.RingQ().MulScalarAndSubLvl)
	}
}

func (eval *evaluator) SubNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	ctOut = eval.newCiphertextBinary(ctIn, op1)
	eval.Sub(ctIn, op1, ctOut)
	return
}

func (eval *evaluator) Neg(ctIn *Ciphertext, ctOut *Ciphertext) {

	if ctIn.Degree() != ctOut.Degree() {
		panic("cannot Negate: invalid receiver Ciphertext does not match input Ciphertext degree")
	}

	level := utils.MinInt(ctIn.Level(), ctOut.Level())

	for i := range ctIn.Value {
		eval.params.RingQ().NegLvl(level, ctIn.Value[i], ctOut.Value[i])
	}

	ctOut.Scale = ctIn.Scale
}

func (eval *evaluator) NegNew(ctIn *Ciphertext) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	eval.Neg(ctIn, ctOut)
	return
}

func (eval *evaluator) AddScalarNew(ctIn *Ciphertext, scalar uint64) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	eval.AddScalar(ctIn, scalar, ctOut)
	return
}

// AddScalar adds a scalar to ctIn and returns the result in ctOut.
func (eval *evaluator) AddScalar(ctIn *Ciphertext, scalar uint64, ctOut *Ciphertext) {

	ringQ := eval.params.RingQ()
	ringT := eval.params.RingT()

	if ctIn.Scale != 1 {
		scalar = ring.BRed(scalar, ctIn.Scale, ringT.Modulus[0], ringT.BredParams[0])
	}

	ringQ.AddScalarLvl(utils.MinInt(ctIn.Level(), ctOut.Level()), ctIn.Value[0], scalar, ctOut.Value[0])

	if ctIn != ctOut {
		for i := 1; i < ctIn.Degree()+1; i++ {
			ring.CopyValues(ctIn.Value[i], ctOut.Value[i])
		}

		ctOut.Scale = ctIn.Scale
	}
}

func (eval *evaluator) MulScalarNew(ctIn *Ciphertext, scalar uint64) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ctIn.Degree(), ctIn.Level(), ctIn.Scale)
	eval.MulScalar(ctIn, scalar, ctOut)
	return
}

// MulScalar multiplies ctIn with a scalar and returns the result in ctOut.
func (eval *evaluator) MulScalar(ctIn *Ciphertext, scalar uint64, ctOut *Ciphertext) {
	ringQ := eval.params.RingQ()
	for i := 0; i < ctIn.Degree()+1; i++ {
		ringQ.MulScalarLvl(utils.MinInt(ctIn.Level(), ctOut.Level()), ctIn.Value[i], scalar, ctOut.Value[i])
	}
}

// MulScalarAndAdd multiplies ctIn with a scalar adds the result on ctOut.
func (eval *evaluator) MulScalarAndAdd(ctIn *Ciphertext, scalar uint64, ctOut *Ciphertext) {
	ringQ := eval.params.RingQ()

	// scalar *= (ctOut.Scale / ctIn.Scale)
	if ctIn.Scale != ctOut.Scale {
		ringT := eval.params.RingT()
		ratio := ring.ModExp(ctIn.Scale, ringT.Modulus[0]-2, ringT.Modulus[0])
		ratio = ring.BRed(ratio, ctOut.Scale, ringT.Modulus[0], ringT.BredParams[0])
		scalar = ring.BRed(ratio, scalar, ringT.Modulus[0], ringT.BredParams[0])
	}

	for i := 0; i < ctIn.Degree()+1; i++ {
		ringQ.MulScalarAndAddLvl(utils.MinInt(ctIn.Level(), ctOut.Level()), ctIn.Value[i], scalar, ctOut.Value[i])
	}
}

// DropLevelNew reduces the level of ctIn by levels and returns the result in a newly created element.
// No rescaling is applied during this procedure.
func (eval *evaluator) DropLevelNew(ctIn *Ciphertext, levels int) (ctOut *Ciphertext) {
	ctOut = ctIn.CopyNew()
	eval.DropLevel(ctOut, levels)
	return
}

// DropLevel reduces the level of ctIn by levels and returns the result in ctIn.
// No rescaling is applied during this procedure.
func (eval *evaluator) DropLevel(ctIn *Ciphertext, levels int) {
	level := ctIn.Level()
	for i := range ctIn.Value {
		ctIn.Value[i].Coeffs = ctIn.Value[i].Coeffs[:level+1-levels]
	}
}

// MulNew multiplies ctIn with op1 without relinearization and returns the result in a newly created element.
// The procedure will panic if either ctIn.Degree or op1.Degree > 1.
func (eval *evaluator) MulNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, ctIn.Degree()+op1.Degree(), utils.MinInt(ctIn.Level(), op1.Level()), 0)
	eval.mulRelin(ctIn, op1, false, ctOut)
	return
}

// Mul multiplies ctIn with op1 without relinearization and returns the result in ctOut.
// The procedure will panic if either ctIn or op1 are have a degree higher than 1.
// The procedure will panic if ctOut.Degree != ctIn.Degree + op1.Degree.
func (eval *evaluator) Mul(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelin(ctIn, op1, false, ctOut)
}

// MulRelinNew multiplies ctIn with op1 with relinearization and returns the result in a newly created element.
// The procedure will panic if either ctIn.Degree or op1.Degree > 1.
// The procedure will panic if the evaluator was not created with an relinearization key.
func (eval *evaluator) MulRelinNew(ctIn *Ciphertext, op1 Operand) (ctOut *Ciphertext) {
	ctOut = NewCiphertext(eval.params, 1, utils.MinInt(ctIn.Level(), op1.Level()), 0)
	eval.mulRelin(ctIn, op1, true, ctOut)
	return
}

// MulRelin multiplies ctIn with op1 with relinearization and returns the result in ctOut.
// The procedure will panic if either ctIn.Degree or op1.Degree > 1.
// The procedure will panic if ctOut.Degree != ctIn.Degree + op1.Degree.
// The procedure will panic if the evaluator was not created with an relinearization key.
func (eval *evaluator) MulRelin(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelin(ctIn, op1, true, ctOut)
}

func (eval *evaluator) mulRelin(op0, op1 Operand, relin bool, ctOut *Ciphertext) {

	eval.checkBinary(op0, op1, ctOut, utils.MaxInt(op0.Degree(), op1.Degree()))

	level := utils.MinInt(utils.MinInt(op0.Level(), op1.Level()), ctOut.Level())

	if ctOut.Level() > level {
		eval.DropLevel(ctOut, ctOut.Level()-level)
	}

	if op0.Degree() > 1 || op1.Degree() > 1 {
		panic("cannot MulRelin: input elements must be of degree 0 or 1")
	}

	ringT := eval.params.RingT()

	ctOut.Scale = ring.BRed(op0.ScalingFactor(), op1.ScalingFactor(), ringT.Modulus[0], ringT.BredParams[0])

	ringQ := eval.params.RingQ()

	var c00, c01, c0, c1, c2 *ring.Poly

	// Case Ciphertext (x) Ciphertext
	if op0.Degree()+op1.Degree() == 2 {

		c00 = eval.buffQ[0]
		c01 = eval.buffQ[1]

		c0 = ctOut.Value[0]
		c1 = ctOut.Value[1]

		if !relin {
			if ctOut.Degree() < 2 {
				ctOut.El().Resize(eval.params.Parameters, 2)
			}
			c2 = ctOut.Value[2]
		} else {
			c2 = eval.buffQ[2]
		}

		// Avoid overwriting if the second input is the output
		var tmp0, tmp1 *rlwe.Ciphertext
		if op1.El() == ctOut.El() {
			tmp0, tmp1 = op1.El(), op0.El()
		} else {
			tmp0, tmp1 = op0.El(), op1.El()
		}

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MFormLvl(level, tmp0.Value[1], c01)

		if op0 == op1 { // squaring case
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[0], c0) // c0 = c[0]*c[0]
			ringQ.MulCoeffsMontgomeryLvl(level, c01, tmp1.Value[1], c2) // c2 = c[1]*c[1]
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[1], c1) // c1 = 2*c[0]*c[1]
			ringQ.AddLvl(level, c1, c1, c1)

		} else { // regular case
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[0], c0) // c0 = c0[0]*c0[0]
			ringQ.MulCoeffsMontgomeryLvl(level, c01, tmp1.Value[1], c2) // c2 = c0[1]*c1[1]
			ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[1], c1)
			ringQ.MulCoeffsMontgomeryAndAddLvl(level, c01, tmp1.Value[0], c1) // c1 = c0[0]*c1[1] + c0[1]*c1[0]
		}

		if relin {

			// Yup...
			ringQ.MulScalarBigintLvl(level, c2, eval.tInvModQ[level], c2)

			eval.GadgetProduct(level, c2, eval.Rlk.Keys[0].Ciphertext, eval.BuffQP[1].Q, eval.BuffQP[2].Q)

			// It works >.>
			ringQ.MulScalarAndAddLvl(level, eval.BuffQP[1].Q, eval.params.T(), ctOut.Value[0])
			ringQ.MulScalarAndAddLvl(level, eval.BuffQP[2].Q, eval.params.T(), ctOut.Value[1])
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		var tmp0, tmp1 *rlwe.Ciphertext

		if op0.Degree() == 1 {
			tmp0, tmp1 = op1.El(), op0.El()
		} else {
			tmp0, tmp1 = op0.El(), op1.El()
		}

		c00 := eval.buffQ[0]

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[0], ctOut.Value[0])
		ringQ.MulCoeffsMontgomeryLvl(level, c00, tmp1.Value[1], ctOut.Value[1])
	}
}

func (eval *evaluator) MulAndAdd(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelinAndAdd(ctIn, op1, false, ctOut)
}

func (eval *evaluator) MulRelinAndAdd(ctIn *Ciphertext, op1 Operand, ctOut *Ciphertext) {
	eval.mulRelinAndAdd(ctIn, op1, true, ctOut)
}

func (eval *evaluator) mulRelinAndAdd(ctIn *Ciphertext, op1 Operand, relin bool, ctOut *Ciphertext) {

	eval.checkBinary(ctIn, op1, ctOut, utils.MaxInt(ctIn.Degree(), op1.Degree()))

	level := utils.MinInt(utils.MinInt(ctIn.Level(), op1.Level()), ctOut.Level())

	if ctOut.Level() > level {
		eval.DropLevel(ctOut, ctOut.Level()-level)
	}

	if ctIn.Degree() > 1 || op1.Degree() > 1 {
		panic("cannot MulRelinAndAdd: input elements must be of degree 0 or 1")
	}

	if ctIn.El() == ctOut.El() || op1.El() == ctOut.El() {
		panic("ctOut must be different from ctIn and op1")
	}

	ringQ := eval.params.RingQ()
	ringT := eval.params.RingT()

	var c00, c01, c0, c1, c2 *ring.Poly

	// Case Ciphertext (x) Ciphertext
	if ctIn.Degree()+op1.Degree() == 2 {

		c00 = eval.buffQ[0]
		c01 = eval.buffQ[1]

		c0 = ctOut.Value[0]
		c1 = ctOut.Value[1]

		if !relin {
			if ctOut.Degree() < 2 {
				ctOut.El().Resize(eval.params.Parameters, 2)
			}
			c2 = ctOut.Value[2]
		} else {
			c2 = eval.buffQ[2]
		}

		tmp0, tmp1 := ctIn.El(), op1.El()

		var r0, r1 uint64 = 1, 1
		if targetScale := ring.BRed(ctIn.Scale, op1.ScalingFactor(), ringT.Modulus[0], ringT.BredParams[0]); targetScale != ctOut.Scale {
			r0, r1, _ = eval.matchScalesBinary(targetScale, ctOut.Scale)

			for i := range ctOut.Value {
				ringQ.MulScalarLvl(level, ctOut.Value[i], r1, ctOut.Value[i])
			}

			ctOut.Scale = ring.BRed(ctOut.Scale, r1, ringT.Modulus[0], ringT.BredParams[0])
		}

		ringQ.MFormLvl(level, tmp0.Value[0], c00)
		ringQ.MFormLvl(level, tmp0.Value[1], c01)

		if r0 != 1 {
			ringQ.MulScalarLvl(level, c00, r0, c00)
			ringQ.MulScalarLvl(level, c01, r0, c01)
		}

		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[0], c0) // c0 += c[0]*c[0]
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[1], c1) // c1 += c[0]*c[1]
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c01, tmp1.Value[0], c1) // c1 += c[1]*c[0]

		if relin {
			ringQ.MulCoeffsMontgomeryLvl(level, c01, tmp1.Value[1], c2) // c2 += c[1]*c[1]

			ringQ.MulScalarBigintLvl(level, c2, eval.tInvModQ[level], c2)

			eval.GadgetProduct(level, c2, eval.Rlk.Keys[0].Ciphertext, eval.BuffQP[1].Q, eval.BuffQP[2].Q)

			ringQ.MulScalarAndAddLvl(level, eval.BuffQP[1].Q, eval.params.T(), c0)
			ringQ.MulScalarAndAddLvl(level, eval.BuffQP[2].Q, eval.params.T(), c1)

		} else {
			ringQ.MulCoeffsMontgomeryAndAddLvl(level, c01, tmp1.Value[1], c2) // c2 += c[1]*c[1]
		}

		// Case Plaintext (x) Ciphertext or Ciphertext (x) Plaintext
	} else {

		var tmp0, tmp1 *rlwe.Ciphertext

		if ctIn.Degree() == 1 {
			tmp0, tmp1 = op1.El(), ctIn.El()
		} else {
			tmp0, tmp1 = ctIn.El(), op1.El()
		}

		c00 := eval.buffQ[0]

		ringQ.MFormLvl(level, tmp0.Value[0], c00)

		if targetScale := ring.BRed(ctIn.Scale, op1.ScalingFactor(), ringT.Modulus[0], ringT.BredParams[0]); targetScale != ctOut.Scale {
			r1 := ring.ModExp(targetScale, ringT.Modulus[0]-2, ringT.Modulus[0])
			r1 = ring.BRed(r1, ctOut.Scale, ringT.Modulus[0], ringT.BredParams[0])
			ringQ.MulScalarLvl(level, c00, r1, c00)
		}

		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[0], ctOut.Value[0])
		ringQ.MulCoeffsMontgomeryAndAddLvl(level, c00, tmp1.Value[1], ctOut.Value[1])
	}
}

func (eval *evaluator) rescaleOriginal(ctIn, ctOut *Ciphertext) (err error) {

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

		// buff1 = (buff0 * -qL^-1) % t
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

	ctOut.Scale = ring.MRed(ringT.Modulus[0]-ctOut.Scale, eval.qiInvModTNeg[level], ringT.Modulus[0], ringT.MredParams[0])

	return
}

// Rescale divides (rounded) ctIn by the last modulus of the moduli chain and returns the result on ctOut.
// This procesure divides the error by the last modulus of the moduli chain while preserving
// the LSB-plaintext bits.
// The procedure will return an error if:
//     1) ctIn.Level() == 0 (the input ciphertext is already at the last modulus)
//     2) ctOut.Level() < ctIn.Level() - 1 (not enough space to store the result)
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

	// Center by (qL-1)/2
	qL := ringQ.Modulus[level]
	qLHalf := (qL - 1) >> 1
	T := ringT.Modulus[0]

	buff0 := eval.BuffQP[0].Q
	buff1 := eval.BuffQP[1].Q

	for i := range ctIn.Value {

		ringQ.MulScalarBigintLvl(level, ctIn.Value[i], eval.tInvModQ[level], buff0)
		ringQ.InvNTTSingleLazy(level, buff0.Coeffs[level], buff1.Coeffs[level])
		ring.AddScalarVec(buff1.Coeffs[level], buff1.Coeffs[level], qLHalf, qL)

		for j := 0; j < level; j++ {

			qi := ringQ.Modulus[j]
			bredParams := ringQ.BredParams[j]
			mredParams := ringQ.MredParams[j]
			rescaleParams := ring.BRed(T, ringQ.RescaleParams[level-1][j], qi, bredParams)

			ring.AddScalarNoModVec(buff1.Coeffs[level], buff1.Coeffs[j], qi-ring.BRedAdd(qLHalf, qi, bredParams))
			ringQ.NTTSingleLazy(j, buff1.Coeffs[j], buff1.Coeffs[j])
			ring.SubVecAndMulScalarMontgomeryTwoQiVec(buff1.Coeffs[j], buff0.Coeffs[j], ctOut.Value[i].Coeffs[j], rescaleParams, qi, mredParams)
		}

		ctOut.Value[i].Coeffs = ctOut.Value[i].Coeffs[:level]
	}

	ctOut.Scale = ring.MRed(T-ctOut.Scale, eval.qiInvModTNeg[level], T, ringT.MredParams[0])

	return
}

// MatchScales updates the both input ciphertexts to ensures that their scale matches.
// To do so it computes t0 * a = ct1 * b such that:
// - ct0.Scale * a = ct1.Scale: make the scales match.
// - gcd(a, T) == gcd(b, T) == 1: ensure that the new scale is not a zero divisor if T is not prime.
// - |a+b| is minimal: minimize the added noise by the procedure.
func (eval *evaluator) MatchScalesAndLevel(ct0, ct1 *Ciphertext) {

	r0, r1, _ := eval.matchScalesBinary(ct0.Scale, ct1.Scale)

	level := utils.MinInt(ct0.Level(), ct1.Level())

	ringQ := eval.params.RingQ()
	ringT := eval.params.RingT()

	t := ringT.Modulus[0]
	bredParams := ringT.BredParams[0]

	for _, el := range ct0.Value {
		ringQ.MulScalarLvl(level, el, r0, el)
		el.Coeffs = el.Coeffs[:level+1]
	}

	ct0.Scale = ring.BRed(ct0.Scale, r0, t, bredParams)

	for _, el := range ct1.Value {
		ringQ.MulScalarLvl(level, el, r1, el)
		el.Coeffs = el.Coeffs[:level+1]
	}

	ct1.Scale = ring.BRed(ct1.Scale, r1, t, bredParams)
}

func (eval *evaluator) matchScalesBinary(scale0, scale1 uint64) (r0, r1, e uint64) {

	ringT := eval.params.RingT()

	t := ringT.Modulus[0]
	tHalf := t >> 1
	bredParams := ringT.BredParams[0]

	if ring.GCD(scale0, t) != 1 {
		panic("invalid ciphertext scale: gcd(scale, t) != 1")
	}

	var a uint64 = ringT.Modulus[0]
	var b uint64 = 0
	var A uint64 = ring.BRed(ring.ModExp(scale0, t-2, t), scale1, t, bredParams)
	var B uint64 = 1

	e = center(A, tHalf, t) + 1

	for A != 0 {
		q := a / A
		a, A = A, a%A
		b, B = B, ring.CRed(t+b-ring.BRed(B, q, t, bredParams), t)

		if A != 0 && ring.GCD(A, t) == 1 {
			tmp := center(A, tHalf, t) + center(B, tHalf, t)
			if tmp < e {
				e = tmp
				r0, r1 = A, B
			}
		}
	}

	return
}

func center(x, thalf, t uint64) uint64 {
	if x >= thalf {
		return t - x
	}
	return x
}
