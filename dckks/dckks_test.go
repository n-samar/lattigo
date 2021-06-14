package dckks

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/drlwe"
	"github.com/ldsec/lattigo/v2/ring"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/ldsec/lattigo/v2/utils"
)

var flagLongTest = flag.Bool("long", false, "run the long test suite (all parameters). Overrides -short and requires -timeout=0.")
var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")
var printPrecisionStats = flag.Bool("print-precision", false, "print precision stats")
var minPrec float64 = 15.0
var parties int = 1

func testString(opname string, parties int, params ckks.Parameters) string {
	return fmt.Sprintf("%sparties=%d/logN=%d/logQ=%d/levels=%d/alpha=%d/beta=%d",
		opname,
		parties,
		params.LogN(),
		params.LogQP(),
		params.MaxLevel()+1,
		params.PCount(),
		params.Beta())
}

type testContext struct {
	params ckks.Parameters

	dckksContext *dckksContext

	prng utils.PRNG

	encoder   ckks.Encoder
	evaluator ckks.Evaluator

	encryptorPk0 ckks.Encryptor
	decryptorSk0 ckks.Decryptor
	decryptorSk1 ckks.Decryptor

	pk0 *rlwe.PublicKey
	pk1 *rlwe.PublicKey

	sk0 *rlwe.SecretKey
	sk1 *rlwe.SecretKey

	sk0Shards []*rlwe.SecretKey
	sk1Shards []*rlwe.SecretKey
}

func TestDCKKS(t *testing.T) {

	var defaultParams = ckks.DefaultParams[:4] // the default test runs for ring degree N=2^12, 2^13, 2^14, 2^15
	if testing.Short() {
		defaultParams = ckks.DefaultParams[:2] // the short test runs for ring degree N=2^12, 2^13
	}
	if *flagLongTest {
		defaultParams = ckks.DefaultParams // the long test suite runs for all default parameters
	}
	if *flagParamString != "" {
		var jsonParams ckks.ParametersLiteral
		json.Unmarshal([]byte(*flagParamString), &jsonParams)
		defaultParams = []ckks.ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, p := range defaultParams {

		params, err := ckks.NewParametersFromLiteral(p)
		if err != nil {
			panic(err)
		}

		var testCtx *testContext
		if testCtx, err = genTestParams(params); err != nil {
			panic(err)
		}

		testPublicKeyGen(testCtx, t)
		testRelinKeyGen(testCtx, t)
		testKeyswitching(testCtx, t)
		testPublicKeySwitching(testCtx, t)
		testRotKeyGenConjugate(testCtx, t)
		testRotKeyGenCols(testCtx, t)
		testRefresh(testCtx, t)
		testE2SProtocol(testCtx, t)
		testRefreshAndPermute(testCtx, t)
	}
}

func testE2SProtocol(testCtx *testContext, t *testing.T) {

	type Party struct {
		e2s            *E2SProtocol
		s2e            *S2EProtocol
		sk             *rlwe.SecretKey
		publicShareE2S *drlwe.CKSShare
		publicShareS2E *drlwe.CKSShare
		secretShare    rlwe.AdditiveShare
	}

	coeffs, _, ciphertext := newTestVectors(testCtx, testCtx.encryptorPk0, 1, t)

	testCtx.evaluator.DropLevel(ciphertext, 1)

	params := testCtx.params
	P := make([]Party, parties)
	for i := range P {
		P[i].e2s = NewE2SProtocol(params, 3.2)
		P[i].s2e = NewS2EProtocol(params, 3.2)
		P[i].sk = testCtx.sk0Shards[i]
		P[i].publicShareE2S = P[i].e2s.AllocateShareAtLevel(ciphertext.Level())
		P[i].publicShareS2E = P[i].s2e.AllocateShareAtLevel(params.Parameters.MaxLevel())
		P[i].secretShare = rlwe.NewAdditiveShareAtLevel(params.Parameters, ciphertext.Level())
	}

	t.Run(testString("E2SProtocol/", parties, testCtx.params), func(t *testing.T) {

		for i, p := range P {
			p.e2s.GenShare(p.sk, len(P), ciphertext, p.secretShare, p.publicShareE2S)
			if i > 0 {
				p.e2s.AggregateShares(P[0].publicShareE2S, p.publicShareE2S, P[0].publicShareE2S)
			}
		}

		P[0].e2s.GetShare(&P[0].secretShare, P[0].publicShareE2S, ciphertext, &P[0].secretShare)

		rec := rlwe.NewAdditiveShareAtLevel(params.Parameters, ciphertext.Level())
		for _, p := range P {
			testCtx.dckksContext.ringQ.AddLvl(ciphertext.Level(), &rec.Value, &p.secretShare.Value, &rec.Value)
		}

		pt := ckks.NewPlaintext(testCtx.params, ciphertext.Level(), ciphertext.Scale())
		pt.Value[0].Copy(&rec.Value)

		verifyTestVectors(testCtx, nil, coeffs, pt, t)

		crs := ring.NewUniformSampler(testCtx.prng, testCtx.dckksContext.ringQ)
		c1 := crs.ReadLvlNew(params.Parameters.MaxLevel())

		for i, p := range P {

			p.s2e.GenShare(p.sk, c1, p.secretShare, p.publicShareS2E)

			if i > 0 {
				p.s2e.AggregateShares(P[0].publicShareS2E, p.publicShareS2E, P[0].publicShareS2E)
			}
		}

		ctRec := ckks.NewCiphertext(testCtx.params, 1, params.Parameters.MaxLevel(), ciphertext.Scale())
		P[0].s2e.GetEncryption(P[0].publicShareS2E, c1, *ctRec)

		verifyTestVectors(testCtx, testCtx.decryptorSk0, coeffs, ctRec, t)

	})
}

func genTestParams(defaultParams ckks.Parameters) (testCtx *testContext, err error) {

	testCtx = new(testContext)

	testCtx.params = defaultParams

	testCtx.dckksContext = newDckksContext(testCtx.params)

	if testCtx.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	testCtx.encoder = ckks.NewEncoder(testCtx.params)
	testCtx.evaluator = ckks.NewEvaluator(testCtx.params, rlwe.EvaluationKey{})

	kgen := ckks.NewKeyGenerator(testCtx.params)

	// SecretKeys
	testCtx.sk0Shards = make([]*rlwe.SecretKey, parties)
	testCtx.sk1Shards = make([]*rlwe.SecretKey, parties)
	tmp0 := testCtx.dckksContext.ringQP.NewPoly()
	tmp1 := testCtx.dckksContext.ringQP.NewPoly()

	for j := 0; j < parties; j++ {
		testCtx.sk0Shards[j] = kgen.GenSecretKey()
		testCtx.sk1Shards[j] = kgen.GenSecretKey()
		testCtx.dckksContext.ringQP.Add(tmp0, testCtx.sk0Shards[j].Value, tmp0)
		testCtx.dckksContext.ringQP.Add(tmp1, testCtx.sk1Shards[j].Value, tmp1)
	}

	testCtx.sk0 = ckks.NewSecretKey(testCtx.params)
	testCtx.sk1 = ckks.NewSecretKey(testCtx.params)
	testCtx.sk0.Value.Copy(tmp0)
	testCtx.sk1.Value.Copy(tmp1)

	// Publickeys
	testCtx.pk0 = kgen.GenPublicKey(testCtx.sk0)
	testCtx.pk1 = kgen.GenPublicKey(testCtx.sk1)

	testCtx.encryptorPk0 = ckks.NewEncryptorFromPk(testCtx.params, testCtx.pk0)
	testCtx.decryptorSk0 = ckks.NewDecryptor(testCtx.params, testCtx.sk0)
	testCtx.decryptorSk1 = ckks.NewDecryptor(testCtx.params, testCtx.sk1)

	return
}

func testPublicKeyGen(testCtx *testContext, t *testing.T) {

	decryptorSk0 := testCtx.decryptorSk0
	sk0Shards := testCtx.sk0Shards

	crpGenerator := ring.NewUniformSampler(testCtx.prng, testCtx.dckksContext.ringQP)

	t.Run(testString("PublicKeyGen/", parties, testCtx.params), func(t *testing.T) {

		crp := crpGenerator.ReadNew()

		type Party struct {
			*CKGProtocol
			s  *rlwe.SecretKey
			s1 *drlwe.CKGShare
		}

		ckgParties := make([]*Party, parties)
		for i := 0; i < parties; i++ {
			p := new(Party)
			p.CKGProtocol = NewCKGProtocol(testCtx.params)
			p.s = sk0Shards[i]
			p.s1 = p.AllocateShares()
			ckgParties[i] = p
		}
		P0 := ckgParties[0]

		var _ drlwe.CollectivePublicKeyGenerator = P0.CKGProtocol

		// Each party creates a new CKGProtocol instance
		for i, p := range ckgParties {
			p.GenShare(p.s, crp, p.s1)
			if i > 0 {
				P0.AggregateShares(p.s1, P0.s1, P0.s1)
			}
		}

		pk := ckks.NewPublicKey(testCtx.params)
		P0.GenPublicKey(P0.s1, crp, pk)

		// Verifies that decrypt((encryptp(collectiveSk, m), collectivePk) = m
		encryptorTest := ckks.NewEncryptorFromPk(testCtx.params, pk)

		coeffs, _, ciphertext := newTestVectors(testCtx, encryptorTest, 1, t)

		verifyTestVectors(testCtx, decryptorSk0, coeffs, ciphertext, t)
	})

}

func testRelinKeyGen(testCtx *testContext, t *testing.T) {

	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk0 := testCtx.decryptorSk0
	sk0Shards := testCtx.sk0Shards

	t.Run(testString("RelinKeyGen/", parties, testCtx.params), func(t *testing.T) {

		type Party struct {
			*RKGProtocol
			ephSk  *rlwe.SecretKey
			sk     *rlwe.SecretKey
			share1 *drlwe.RKGShare
			share2 *drlwe.RKGShare
		}

		rkgParties := make([]*Party, parties)

		for i := range rkgParties {
			p := new(Party)
			p.RKGProtocol = NewRKGProtocol(testCtx.params)
			p.sk = sk0Shards[i]
			p.ephSk, p.share1, p.share2 = p.AllocateShares()
			rkgParties[i] = p
		}

		P0 := rkgParties[0]

		// Checks that ckks.RKGProtocol complies to the drlwe.RelinearizationKeyGenerator interface
		var _ drlwe.RelinearizationKeyGenerator = P0.RKGProtocol

		crpGenerator := ring.NewUniformSampler(testCtx.prng, testCtx.dckksContext.ringQP)
		crp := make([]*ring.Poly, testCtx.params.Beta())

		for i := 0; i < testCtx.params.Beta(); i++ {
			crp[i] = crpGenerator.ReadNew()
		}

		// ROUND 1
		for i, p := range rkgParties {
			p.GenShareRoundOne(p.sk, crp, p.ephSk, p.share1)
			if i > 0 {
				P0.AggregateShares(p.share1, P0.share1, P0.share1)
			}
		}

		//ROUND 2
		for i, p := range rkgParties {
			p.GenShareRoundTwo(p.ephSk, p.sk, P0.share1, crp, p.share2)
			if i > 0 {
				P0.AggregateShares(p.share2, P0.share2, P0.share2)
			}
		}

		rlk := ckks.NewRelinearizationKey(testCtx.params)
		P0.GenRelinearizationKey(P0.share1, P0.share2, rlk)

		coeffs, _, ciphertext := newTestVectors(testCtx, encryptorPk0, 1, t)

		for i := range coeffs {
			coeffs[i] *= coeffs[i]
		}

		evaluator := testCtx.evaluator.WithKey(rlwe.EvaluationKey{Rlk: rlk, Rtks: nil})
		evaluator.MulRelin(ciphertext, ciphertext, ciphertext)

		evaluator.Rescale(ciphertext, testCtx.params.Scale(), ciphertext)

		require.Equal(t, ciphertext.Degree(), 1)

		verifyTestVectors(testCtx, decryptorSk0, coeffs, ciphertext, t)

	})

}

func testKeyswitching(testCtx *testContext, t *testing.T) {

	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk1 := testCtx.decryptorSk1
	sk0Shards := testCtx.sk0Shards
	sk1Shards := testCtx.sk1Shards

	t.Run(testString("Keyswitching/", parties, testCtx.params), func(t *testing.T) {

		coeffs, _, ciphertextFullLevels := newTestVectors(testCtx, encryptorPk0, 1, t)

		for _, dropped := range []int{0, ciphertextFullLevels.Level()} { // runs the test for full and level zero
			ciphertext := testCtx.evaluator.DropLevelNew(ciphertextFullLevels, dropped)

			t.Run(fmt.Sprintf("atLevel=%d", ciphertext.Level()), func(t *testing.T) {

				type Party struct {
					cks   *CKSProtocol
					s0    *rlwe.SecretKey
					s1    *rlwe.SecretKey
					share *drlwe.CKSShare
				}

				cksParties := make([]*Party, parties)
				for i := 0; i < parties; i++ {
					p := new(Party)
					p.cks = NewCKSProtocol(testCtx.params, 6.36)
					p.s0 = sk0Shards[i]
					p.s1 = sk1Shards[i]
					p.share = p.cks.AllocateShare()
					cksParties[i] = p
				}
				P0 := cksParties[0]

				// Checks that the protocol complies to the drlwe.KeySwitchingProtocol interface
				var _ drlwe.KeySwitchingProtocol = P0.cks

				// Each party creates its CKSProtocol instance with tmp = si-si'
				for i, p := range cksParties {
					p.cks.GenShare(p.s0, p.s1, ciphertext, p.share)
					if i > 0 {
						P0.cks.AggregateShares(p.share, P0.share, P0.share)
					}
				}

				ksCiphertext := ckks.NewCiphertext(testCtx.params, 1, ciphertext.Level(), ciphertext.Scale()/2)

				P0.cks.KeySwitch(P0.share, ciphertext, ksCiphertext)

				verifyTestVectors(testCtx, decryptorSk1, coeffs, ksCiphertext, t)

				P0.cks.KeySwitch(P0.share, ciphertext, ciphertext)

				verifyTestVectors(testCtx, decryptorSk1, coeffs, ksCiphertext, t)

			})
		}
	})
}

func testPublicKeySwitching(testCtx *testContext, t *testing.T) {

	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk1 := testCtx.decryptorSk1
	sk0Shards := testCtx.sk0Shards
	pk1 := testCtx.pk1

	t.Run(testString("PublicKeySwitching/", parties, testCtx.params), func(t *testing.T) {

		coeffs, _, ciphertextFullLevels := newTestVectors(testCtx, encryptorPk0, 1, t)

		for _, dropped := range []int{0, ciphertextFullLevels.Level()} { // runs the test for full and level zero
			ciphertext := testCtx.evaluator.DropLevelNew(ciphertextFullLevels, dropped)

			t.Run(fmt.Sprintf("atLevel=%d", ciphertext.Level()), func(t *testing.T) {

				type Party struct {
					*PCKSProtocol
					s     *rlwe.SecretKey
					share *drlwe.PCKSShare
				}

				pcksParties := make([]*Party, parties)
				for i := 0; i < parties; i++ {
					p := new(Party)
					p.PCKSProtocol = NewPCKSProtocol(testCtx.params, 6.36)
					p.s = sk0Shards[i]
					p.share = p.AllocateShares(ciphertext.Level())
					pcksParties[i] = p
				}
				P0 := pcksParties[0]

				// Checks that the protocol complies to the drlwe.KeySwitchingProtocol interface
				var _ drlwe.PublicKeySwitchingProtocol = P0.PCKSProtocol

				ciphertextSwitched := ckks.NewCiphertext(testCtx.params, 1, ciphertext.Level(), ciphertext.Scale())

				for i, p := range pcksParties {
					p.GenShare(p.s, pk1, ciphertext, p.share)
					if i > 0 {
						P0.AggregateShares(p.share, P0.share, P0.share)
					}
				}

				P0.KeySwitchCKKSCiphertext(P0.share, ciphertext, ciphertextSwitched)

				verifyTestVectors(testCtx, decryptorSk1, coeffs, ciphertextSwitched, t)
			})
		}

	})
}

func testRotKeyGenConjugate(testCtx *testContext, t *testing.T) {

	ringQP := testCtx.dckksContext.ringQP
	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk0 := testCtx.decryptorSk0
	sk0Shards := testCtx.sk0Shards

	t.Run(testString("RotKeyGenConjugate/", parties, testCtx.params), func(t *testing.T) {

		type Party struct {
			*RTGProtocol
			s     *rlwe.SecretKey
			share *drlwe.RTGShare
		}

		pcksParties := make([]*Party, parties)
		for i := 0; i < parties; i++ {
			p := new(Party)
			p.RTGProtocol = NewRotKGProtocol(testCtx.params)
			p.s = sk0Shards[i]
			p.share = p.AllocateShares()
			pcksParties[i] = p
		}
		P0 := pcksParties[0]

		// checks that ckks.RTGProtocol complies to the drlwe.RotationKeyGenerator interface
		var _ drlwe.RotationKeyGenerator = P0.RTGProtocol

		crpGenerator := ring.NewUniformSampler(testCtx.prng, testCtx.dckksContext.ringQP)
		crp := make([]*ring.Poly, testCtx.params.Beta())

		for i := 0; i < testCtx.params.Beta(); i++ {
			crp[i] = crpGenerator.ReadNew()
		}

		galEl := testCtx.params.GaloisElementForRowRotation()
		rotKeySet := ckks.NewRotationKeySet(testCtx.params, []uint64{galEl})

		for i, p := range pcksParties {
			p.GenShare(p.s, galEl, crp, p.share)
			if i > 0 {
				P0.Aggregate(p.share, P0.share, P0.share)
			}
		}

		P0.GenRotationKey(P0.share, crp, rotKeySet.Keys[galEl])

		coeffs, _, ciphertext := newTestVectors(testCtx, encryptorPk0, 1, t)

		evaluator := testCtx.evaluator.WithKey(rlwe.EvaluationKey{Rlk: nil, Rtks: rotKeySet})
		evaluator.Conjugate(ciphertext, ciphertext)

		coeffsWant := make([]complex128, ringQP.N>>1)

		for i := 0; i < ringQP.N>>1; i++ {
			coeffsWant[i] = complex(real(coeffs[i]), -imag(coeffs[i]))
		}

		verifyTestVectors(testCtx, decryptorSk0, coeffsWant, ciphertext, t)

	})
}

func testRotKeyGenCols(testCtx *testContext, t *testing.T) {

	ringQP := testCtx.dckksContext.ringQP
	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk0 := testCtx.decryptorSk0
	sk0Shards := testCtx.sk0Shards

	t.Run(testString("RotKeyGenCols/", parties, testCtx.params), func(t *testing.T) {

		type Party struct {
			*RTGProtocol
			s     *rlwe.SecretKey
			share *drlwe.RTGShare
		}

		pcksParties := make([]*Party, parties)
		for i := 0; i < parties; i++ {
			p := new(Party)
			p.RTGProtocol = NewRotKGProtocol(testCtx.params)
			p.s = sk0Shards[i]
			p.share = p.AllocateShares()
			pcksParties[i] = p
		}

		P0 := pcksParties[0]

		crpGenerator := ring.NewUniformSampler(testCtx.prng, ringQP)
		crp := make([]*ring.Poly, testCtx.params.Beta())

		for i := 0; i < testCtx.params.Beta(); i++ {
			crp[i] = crpGenerator.ReadNew()
		}

		coeffs, _, ciphertext := newTestVectors(testCtx, encryptorPk0, 1, t)

		receiver := ckks.NewCiphertext(testCtx.params, ciphertext.Degree(), ciphertext.Level(), ciphertext.Scale())

		galEls := testCtx.params.GaloisElementsForRowInnerSum()
		rotKeySet := ckks.NewRotationKeySet(testCtx.params, galEls)

		for _, galEl := range galEls {
			for i, p := range pcksParties {
				p.GenShare(p.s, galEl, crp, p.share)
				if i > 0 {
					P0.Aggregate(p.share, P0.share, P0.share)
				}
			}
			P0.GenRotationKey(P0.share, crp, rotKeySet.Keys[galEl])
		}

		evaluator := testCtx.evaluator.WithKey(rlwe.EvaluationKey{Rlk: nil, Rtks: rotKeySet})

		for k := 1; k < ringQP.N>>1; k <<= 1 {
			evaluator.Rotate(ciphertext, int(k), receiver)

			coeffsWant := utils.RotateComplex128Slice(coeffs, int(k))

			verifyTestVectors(testCtx, decryptorSk0, coeffsWant, receiver, t)
		}
	})
}

func testRefresh(testCtx *testContext, t *testing.T) {

	evaluator := testCtx.evaluator
	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk0 := testCtx.decryptorSk0
	sk0Shards := testCtx.sk0Shards

	levelStart := 3

	t.Run(testString("Refresh/", parties, testCtx.params), func(t *testing.T) {

		if testCtx.params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		type Party struct {
			*RefreshProtocol
			s      *ring.Poly
			share1 RefreshShareDecrypt
			share2 RefreshShareRecrypt
		}

		RefreshParties := make([]*Party, parties)
		for i := 0; i < parties; i++ {
			p := new(Party)
			p.RefreshProtocol = NewRefreshProtocol(testCtx.params)
			p.s = sk0Shards[i].Value
			p.share1, p.share2 = p.AllocateShares(levelStart)
			RefreshParties[i] = p
		}

		P0 := RefreshParties[0]

		crpGenerator := ring.NewUniformSampler(testCtx.prng, testCtx.dckksContext.ringQ)
		crp := crpGenerator.ReadNew()

		coeffs, _, ciphertext := newTestVectors(testCtx, encryptorPk0, 1.0, t)

		for ciphertext.Level() != levelStart {
			evaluator.DropLevel(ciphertext, 1)
		}

		for i, p := range RefreshParties {
			p.GenShares(p.s, levelStart, parties, ciphertext, testCtx.params.Scale(), crp, p.share1, p.share2)
			if i > 0 {
				P0.Aggregate(p.share1, P0.share1, P0.share1)
				P0.Aggregate(p.share2, P0.share2, P0.share2)
			}
		}

		// We refresh the ciphertext with the simulated error
		P0.Decrypt(ciphertext, P0.share1)             // Masked decryption
		P0.Recode(ciphertext, testCtx.params.Scale()) // Masked re-encoding
		P0.Recrypt(ciphertext, crp, P0.share2)        // Masked re-encryption

		require.Equal(t, ciphertext.Level(), testCtx.params.MaxLevel())

		verifyTestVectors(testCtx, decryptorSk0, coeffs, ciphertext, t)

	})
}

func testRefreshAndPermute(testCtx *testContext, t *testing.T) {

	evaluator := testCtx.evaluator
	encryptorPk0 := testCtx.encryptorPk0
	decryptorSk0 := testCtx.decryptorSk0
	sk0Shards := testCtx.sk0Shards

	levelStart := 3

	t.Run(testString("RefreshAndPermute/", parties, testCtx.params), func(t *testing.T) {

		if testCtx.params.MaxLevel() < 3 {
			t.Skip("skipping test for params max level < 3")
		}

		type Party struct {
			*PermuteProtocol
			s      *ring.Poly
			share1 RefreshShareDecrypt
			share2 RefreshShareRecrypt
		}

		RefreshParties := make([]*Party, parties)
		for i := 0; i < parties; i++ {
			p := new(Party)
			p.PermuteProtocol = NewPermuteProtocol(testCtx.params)
			p.s = sk0Shards[i].Value
			p.share1, p.share2 = p.AllocateShares(levelStart)
			RefreshParties[i] = p
		}

		P0 := RefreshParties[0]

		crpGenerator := ring.NewUniformSampler(testCtx.prng, testCtx.dckksContext.ringQ)
		crp := crpGenerator.ReadNew()

		coeffs, _, ciphertext := newTestVectors(testCtx, encryptorPk0, 1.0, t)

		for ciphertext.Level() != levelStart {
			evaluator.DropLevel(ciphertext, 1)
		}

		permutation := make([]uint64, testCtx.params.Slots())

		for i := range permutation {
			permutation[i] = ring.RandUniform(testCtx.prng, uint64(testCtx.params.Slots()), uint64(testCtx.params.Slots()-1))
		}

		for i, p := range RefreshParties {
			p.GenShares(p.s, levelStart, parties, ciphertext, crp, testCtx.params.Slots(), permutation, p.share1, p.share2)
			if i > 0 {
				P0.Aggregate(p.share1, P0.share1, P0.share1)
				P0.Aggregate(p.share2, P0.share2, P0.share2)
			}
		}

		// We refresh the ciphertext with the simulated error
		P0.Decrypt(ciphertext, P0.share1)                           // Masked decryption
		P0.Permute(ciphertext, permutation, testCtx.params.Slots()) // Masked re-encoding
		P0.Recrypt(ciphertext, crp, P0.share2)                      // Masked re-encryption

		coeffsPermute := make([]complex128, len(coeffs))

		for i := range coeffs {
			coeffsPermute[i] = coeffs[permutation[i]]
		}

		require.Equal(t, ciphertext.Level(), testCtx.params.MaxLevel())

		verifyTestVectors(testCtx, decryptorSk0, coeffsPermute, ciphertext, t)

	})
}

func newTestVectors(testCtx *testContext, encryptor ckks.Encryptor, a float64, t *testing.T) (values []complex128, plaintext *ckks.Plaintext, ciphertext *ckks.Ciphertext) {

	slots := testCtx.params.Slots()

	values = make([]complex128, slots)

	for i := 0; i < slots; i++ {
		values[i] = utils.RandComplex128(-a, a)
	}

	values[0] = complex(0.607538, 0.555668)

	plaintext = testCtx.encoder.EncodeNew(values, testCtx.params.LogSlots())

	ciphertext = encryptor.EncryptNew(plaintext)

	return values, plaintext, ciphertext
}

func verifyTestVectors(testCtx *testContext, decryptor ckks.Decryptor, valuesWant []complex128, element interface{}, t *testing.T) {

	var valuesTest []complex128

	switch element := element.(type) {
	case *ckks.Ciphertext:
		valuesTest = testCtx.encoder.Decode(decryptor.DecryptNew(element), testCtx.params.LogSlots())
	case *ckks.Plaintext:
		valuesTest = testCtx.encoder.Decode(element, testCtx.params.LogSlots())
	case []complex128:
		valuesTest = element
	}

	slots := testCtx.params.Slots()

	var deltaReal, deltaImag float64

	var minprec, maxprec, meanprec, medianprec complex128

	diff := make([]complex128, slots)

	minprec = complex(0, 0)
	maxprec = complex(1, 1)

	meanprec = complex(0, 0)

	distribReal := make(map[uint64]uint64)
	distribImag := make(map[uint64]uint64)

	for i := range valuesWant {

		deltaReal = math.Abs(real(valuesTest[i]) - real(valuesWant[i]))
		deltaImag = math.Abs(imag(valuesTest[i]) - imag(valuesWant[i]))

		diff[i] += complex(deltaReal, 0)
		diff[i] += complex(0, deltaImag)

		meanprec += diff[i]

		if real(diff[i]) > real(minprec) {
			minprec = complex(real(diff[i]), 0)
		}

		if imag(diff[i]) > imag(minprec) {
			minprec = complex(real(minprec), imag(diff[i]))
		}

		if real(diff[i]) < real(maxprec) {
			maxprec = complex(real(diff[i]), 0)
		}

		if imag(diff[i]) < imag(maxprec) {
			maxprec = complex(real(maxprec), imag(diff[i]))
		}

		distribReal[uint64(math.Floor(math.Log2(1/real(diff[i]))))]++
		distribImag[uint64(math.Floor(math.Log2(1/imag(diff[i]))))]++
	}

	meanprec /= complex(float64(slots), 0)
	medianprec = calcmedian(diff)

	if *printPrecisionStats {
		t.Logf("Minimum precision : (%.2f, %.2f) bits \n", math.Log2(1/real(minprec)), math.Log2(1/imag(minprec)))
		t.Logf("Maximum precision : (%.2f, %.2f) bits \n", math.Log2(1/real(maxprec)), math.Log2(1/imag(maxprec)))
		t.Logf("Mean    precision : (%.2f, %.2f) bits \n", math.Log2(1/real(meanprec)), math.Log2(1/imag(meanprec)))
		t.Logf("Median  precision : (%.2f, %.2f) bits \n", math.Log2(1/real(medianprec)), math.Log2(1/imag(medianprec)))
		t.Log()
	}

	require.GreaterOrEqual(t, math.Log2(1/real(medianprec)), minPrec)
	require.GreaterOrEqual(t, math.Log2(1/imag(medianprec)), minPrec)
}

func calcmedian(values []complex128) (median complex128) {

	tmp := make([]float64, len(values))

	for i := range values {
		tmp[i] = real(values[i])
	}

	sort.Float64s(tmp)

	for i := range values {
		values[i] = complex(tmp[i], imag(values[i]))
	}

	for i := range values {
		tmp[i] = imag(values[i])
	}

	sort.Float64s(tmp)

	for i := range values {
		values[i] = complex(real(values[i]), tmp[i])
	}

	index := len(values) / 2

	if len(values)&1 == 1 {
		return values[index]
	}

	if index+1 == len(values) {
		return values[index]
	}

	return (values[index] + values[index+1]) / 2
}
