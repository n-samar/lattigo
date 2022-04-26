package lwe

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math/big"
)

// Handler is a struct that stores necessary
// data to handle LWE <-> RLWE conversion and
// LUT evaluation.
type Handler struct {
	*rlwe.KeySwitcher
	paramsLUT rlwe.Parameters
	paramsLWE rlwe.Parameters
	rtks      *rlwe.RotationKeySet

	xPow         []*ring.Poly  //X^n from 0 to LogN LUT
	xPowMinusOne []rlwe.PolyQP //X^n - 1 from 0 to 2N LWE

	permuteNTTIndex map[uint64][]uint64

	poolMod2N [2]*ring.Poly

	accumulator *rlwe.Ciphertext
	Sk          *rlwe.SecretKey
}

// NewHandler creates a new Handler
func NewHandler(paramsLUT, paramsLWE rlwe.Parameters, rtks *rlwe.RotationKeySet) (h *Handler) {
	h = new(Handler)
	h.KeySwitcher = rlwe.NewKeySwitcher(paramsLUT)
	h.paramsLUT = paramsLUT
	h.paramsLWE = paramsLWE

	ringQ := paramsLUT.RingQ()
	ringP := paramsLUT.RingP()

	h.poolMod2N = [2]*ring.Poly{paramsLWE.RingQ().NewPolyLvl(0), paramsLWE.RingQ().NewPolyLvl(0)}
	h.accumulator = rlwe.NewCiphertextNTT(paramsLUT, 1, paramsLUT.MaxLevel())

	// Compute X^{n} from 0 to LogN LUT
	h.xPow = make([]*ring.Poly, paramsLUT.LogN())
	for i := 0; i < paramsLUT.LogN(); i++ {
		h.xPow[i] = ringQ.NewPoly()
		if i == 0 {
			for j := 0; j < paramsLUT.MaxLevel()+1; j++ {
				h.xPow[i].Coeffs[j][1<<i] = ring.MForm(1, ringQ.Modulus[j], ringQ.BredParams[j])
			}
			ringQ.NTT(h.xPow[i], h.xPow[i])
		} else {
			ringQ.MulCoeffsMontgomery(h.xPow[i-1], h.xPow[i-1], h.xPow[i]) // X^{n} = X^{1} * X^{n-1}
		}
	}

	// Compute X^{n} -  1 from 0 to 2N LWE
	oneNTTMFormQ := ringQ.NewPoly()
	for i := range ringQ.Modulus {
		for j := 0; j < ringQ.N; j++ {
			oneNTTMFormQ.Coeffs[i][j] = ring.MForm(1, ringQ.Modulus[i], ringQ.BredParams[i])
		}
	}

	oneNTTMFormP := ringP.NewPoly()
	for i := range ringP.Modulus {
		for j := 0; j < ringP.N; j++ {
			oneNTTMFormP.Coeffs[i][j] = ring.MForm(1, ringP.Modulus[i], ringP.BredParams[i])
		}
	}

	N := ringQ.N

	h.xPowMinusOne = make([]rlwe.PolyQP, 2*N)
	for i := 0; i < N; i++ {
		h.xPowMinusOne[i].Q = ringQ.NewPoly()
		h.xPowMinusOne[i].P = ringP.NewPoly()
		h.xPowMinusOne[i+N].Q = ringQ.NewPoly()
		h.xPowMinusOne[i+N].P = ringP.NewPoly()
		if i == 0 || i == 1 {
			for j := range ringQ.Modulus {
				h.xPowMinusOne[i].Q.Coeffs[j][i] = ring.MForm(1, ringQ.Modulus[j], ringQ.BredParams[j])
			}

			for j := range ringP.Modulus {
				h.xPowMinusOne[i].P.Coeffs[j][i] = ring.MForm(1, ringP.Modulus[j], ringP.BredParams[j])
			}

			ringQ.NTT(h.xPowMinusOne[i].Q, h.xPowMinusOne[i].Q)
			ringP.NTT(h.xPowMinusOne[i].P, h.xPowMinusOne[i].P)

			// Negacyclic wrap-arround for n > N
			ringQ.Neg(h.xPowMinusOne[i].Q, h.xPowMinusOne[i+N].Q)
			ringP.Neg(h.xPowMinusOne[i].P, h.xPowMinusOne[i+N].P)

		} else {
			ringQ.MulCoeffsMontgomery(h.xPowMinusOne[1].Q, h.xPowMinusOne[i-1].Q, h.xPowMinusOne[i].Q) // X^{n} = X^{1} * X^{n-1}
			ringP.MulCoeffsMontgomery(h.xPowMinusOne[1].P, h.xPowMinusOne[i-1].P, h.xPowMinusOne[i].P)

			// Negacyclic wrap-arround for n > N
			ringQ.Neg(h.xPowMinusOne[i].Q, h.xPowMinusOne[i+N].Q) // X^{2n} = -X^{1} * X^{n-1}
			ringP.Neg(h.xPowMinusOne[i].P, h.xPowMinusOne[i+N].P)
		}
	}

	// Subtract -1 in NTT
	for i := 0; i < 2*N; i++ {
		ringQ.Sub(h.xPowMinusOne[i].Q, oneNTTMFormQ, h.xPowMinusOne[i].Q) // X^{n} - 1
		ringP.Sub(h.xPowMinusOne[i].P, oneNTTMFormP, h.xPowMinusOne[i].P)
	}

	h.rtks = rtks
	h.permuteNTTIndex = *h.permuteNTTIndexesForKey(rtks)

	return
}

func (h *Handler) permuteNTTIndexesForKey(rtks *rlwe.RotationKeySet) *map[uint64][]uint64 {
	if rtks == nil {
		return &map[uint64][]uint64{}
	}
	permuteNTTIndex := make(map[uint64][]uint64, len(rtks.Keys))
	for galEl := range rtks.Keys {
		permuteNTTIndex[galEl] = h.paramsLUT.RingQ().PermuteNTTIndex(galEl)
	}
	return &permuteNTTIndex
}

// LUTKey is a struct storing the encryption
// of the bits of the LWE key.
type LUTKey struct {
	SkPos   []*rlwe.RGSWCiphertext
	SkNeg   []*rlwe.RGSWCiphertext
	OneRGSW []*ring.Poly
}

// GenLUTKey generates the LUT evaluation key
func (h *Handler) GenLUTKey(skRLWE, skLWE *rlwe.SecretKey) (lutkey *LUTKey) {

	paramsLUT := h.paramsLUT
	paramsLWE := h.paramsLWE

	skLWEInvNTT := h.paramsLWE.RingQ().NewPoly()

	paramsLWE.RingQ().InvNTT(skLWE.Value.Q, skLWEInvNTT)

	plaintextRGSWOne := rlwe.NewPlaintext(paramsLUT, paramsLUT.MaxLevel())
	plaintextRGSWOne.Value.IsNTT = true
	for j := 0; j < paramsLUT.QCount(); j++ {
		for i := 0; i < paramsLUT.N(); i++ {
			plaintextRGSWOne.Value.Coeffs[j][i] = 1
		}
	}

	encryptor := rlwe.NewEncryptor(paramsLUT, skRLWE)

	ringQLUT := paramsLUT.RingQ()
	ringPLUT := paramsLUT.RingP()

	levelQ := paramsLUT.QCount() - 1
	levelP := paramsLUT.PCount() - 1

	var pBigInt *big.Int
	if levelP > -1 {
		if levelP == paramsLUT.PCount()-1 {
			pBigInt = ringPLUT.ModulusBigint
		} else {
			P := ringPLUT.Modulus
			pBigInt = new(big.Int).SetUint64(P[0])
			for i := 1; i < levelP+1; i++ {
				pBigInt.Mul(pBigInt, ring.NewUint(P[i]))
			}
		}
	} else {
		pBigInt = ring.NewUint(1)
	}

	OneRGSW := make([]*ring.Poly, paramsLUT.DecompBIT(paramsLUT.QCount()-1, paramsLUT.PCount()-1))
	OneRGSW[0] = ringQLUT.NewPoly()
	tmp := new(big.Int)
	for i := 0; i < levelQ+1; i++ {
		OneRGSW[0].Coeffs[i][0] = tmp.Mod(pBigInt, ring.NewUint(ringQLUT.Modulus[i])).Uint64()
	}

	ringQLUT.NTTLvl(levelQ, OneRGSW[0], OneRGSW[0])
	ringQLUT.MFormLvl(levelQ, OneRGSW[0], OneRGSW[0])

	for i := 1; i < len(OneRGSW); i++ {
		OneRGSW[i] = OneRGSW[0].CopyNew()
		ringQLUT.MulByPow2(OneRGSW[i], i*paramsLUT.LogBase2(), OneRGSW[i])
	}

	skRGSWPos := make([]*rlwe.RGSWCiphertext, paramsLWE.N())
	skRGSWNeg := make([]*rlwe.RGSWCiphertext, paramsLWE.N())

	ringQ := paramsLWE.RingQ()
	Q := ringQ.Modulus[0]
	OneMForm := ring.MForm(1, Q, ringQ.BredParams[0])
	MinusOneMform := ring.MForm(Q-1, Q, ringQ.BredParams[0])

	for i, si := range skLWEInvNTT.Coeffs[0] {

		skRGSWPos[i] = rlwe.NewCiphertextRGSWNTT(paramsLUT, paramsLUT.MaxLevel())
		skRGSWNeg[i] = rlwe.NewCiphertextRGSWNTT(paramsLUT, paramsLUT.MaxLevel())

		// sk_i =  1 -> [RGSW(1), RGSW(0)]
		if si == OneMForm {
			encryptor.EncryptRGSW(plaintextRGSWOne, skRGSWPos[i])
			encryptor.EncryptRGSW(nil, skRGSWNeg[i])
			// sk_i = -1 -> [RGSW(0), RGSW(1)]
		} else if si == MinusOneMform {
			encryptor.EncryptRGSW(nil, skRGSWPos[i])
			encryptor.EncryptRGSW(plaintextRGSWOne, skRGSWNeg[i])
			// sk_i =  0 -> [RGSW(0), RGSW(0)]
		} else {
			encryptor.EncryptRGSW(nil, skRGSWPos[i])
			encryptor.EncryptRGSW(nil, skRGSWNeg[i])
		}
	}

	return &LUTKey{SkPos: skRGSWPos, SkNeg: skRGSWNeg, OneRGSW: OneRGSW}
}

// ReduceRGSW applies a homomorphic modular reduction on the input RGSW ciphertext and returns
// the result on the output RGSW ciphertext.
func ReduceRGSW(rgsw *rlwe.RGSWCiphertext, ringQP *rlwe.RingQP, res *rlwe.RGSWCiphertext) {

	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	for i := range rgsw.Value {
		for _, el := range rgsw.Value[i] {
			ringQ.Reduce(el[0][0].Q, el[0][0].Q)
			ringP.Reduce(el[0][0].P, el[0][0].P)

			ringQ.Reduce(el[0][1].Q, el[0][1].Q)
			ringP.Reduce(el[0][1].P, el[0][1].P)

			ringQ.Reduce(el[1][0].Q, el[1][0].Q)
			ringP.Reduce(el[1][0].P, el[1][0].P)

			ringQ.Reduce(el[1][1].Q, el[1][1].Q)
			ringP.Reduce(el[1][1].P, el[1][1].P)
		}

	}
}

// AddRGSW adds the input RGSW ciphertext on the output RGSW ciphertext.
func AddRGSW(rgsw *rlwe.RGSWCiphertext, ringQP *rlwe.RingQP, res *rlwe.RGSWCiphertext) {

	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	for i := range rgsw.Value {
		for _, el := range rgsw.Value[i] {
			ringQ.AddNoMod(el[0][0].Q, el[0][0].Q, el[0][0].Q)
			ringP.AddNoMod(el[0][0].P, el[0][0].P, el[0][0].P)

			ringQ.AddNoMod(el[0][1].Q, el[0][1].Q, el[0][1].Q)
			ringP.AddNoMod(el[0][1].P, el[0][1].P, el[0][1].P)

			ringQ.AddNoMod(el[1][0].Q, el[1][0].Q, el[1][0].Q)
			ringP.AddNoMod(el[1][0].P, el[1][0].P, el[1][0].P)

			ringQ.AddNoMod(el[1][1].Q, el[1][1].Q, el[1][1].Q)
			ringP.AddNoMod(el[1][1].P, el[1][1].P, el[1][1].P)
		}
	}
}

// MulRGSWByXPowAlphaMinusOne multiplies the input RGSW ciphertext by (X^alpha - 1) and returns the result on the output RGSW ciphertext.
func MulRGSWByXPowAlphaMinusOne(rgsw *rlwe.RGSWCiphertext, powXMinusOne rlwe.PolyQP, ringQP *rlwe.RingQP, res *rlwe.RGSWCiphertext) {

	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	for i := range rgsw.Value {
		for j, el := range rgsw.Value[i] {
			ringQ.MulCoeffsMontgomeryConstant(el[0][0].Q, powXMinusOne.Q, res.Value[i][j][0][0].Q)
			ringP.MulCoeffsMontgomeryConstant(el[0][0].P, powXMinusOne.P, res.Value[i][j][0][0].P)

			ringQ.MulCoeffsMontgomeryConstant(el[0][1].Q, powXMinusOne.Q, res.Value[i][j][0][1].Q)
			ringP.MulCoeffsMontgomeryConstant(el[0][1].P, powXMinusOne.P, res.Value[i][j][0][1].P)

			ringQ.MulCoeffsMontgomeryConstant(el[1][0].Q, powXMinusOne.Q, res.Value[i][j][1][0].Q)
			ringP.MulCoeffsMontgomeryConstant(el[1][0].P, powXMinusOne.P, res.Value[i][j][1][0].P)

			ringQ.MulCoeffsMontgomeryConstant(el[1][1].Q, powXMinusOne.Q, res.Value[i][j][1][1].Q)
			ringP.MulCoeffsMontgomeryConstant(el[1][1].P, powXMinusOne.P, res.Value[i][j][1][1].P)
		}
	}
}

// MulRGSWByXPowAlphaMinusOneAndAdd multiplies the input RGSW ciphertext by (X^alpha - 1) and adds the result on the output RGSW ciphertext.
func MulRGSWByXPowAlphaMinusOneAndAdd(rgsw *rlwe.RGSWCiphertext, powXMinusOne rlwe.PolyQP, ringQP *rlwe.RingQP, res *rlwe.RGSWCiphertext) {

	ringQ := ringQP.RingQ
	ringP := ringQP.RingP

	for i := range rgsw.Value {
		for j, el := range rgsw.Value[i] {
			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(el[0][0].Q, powXMinusOne.Q, res.Value[i][j][0][0].Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(el[0][0].P, powXMinusOne.P, res.Value[i][j][0][0].P)

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(el[0][1].Q, powXMinusOne.Q, res.Value[i][j][0][1].Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(el[0][1].P, powXMinusOne.P, res.Value[i][j][0][1].P)

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(el[1][0].Q, powXMinusOne.Q, res.Value[i][j][1][0].Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(el[1][0].P, powXMinusOne.P, res.Value[i][j][1][0].P)

			ringQ.MulCoeffsMontgomeryConstantAndAddNoMod(el[1][1].Q, powXMinusOne.Q, res.Value[i][j][1][1].Q)
			ringP.MulCoeffsMontgomeryConstantAndAddNoMod(el[1][1].P, powXMinusOne.P, res.Value[i][j][1][1].P)
		}
	}
}
