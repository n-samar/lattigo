package drlwe

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/tuneinsight/lattigo/v4/ring"
	"github.com/tuneinsight/lattigo/v4/rlwe"
	"github.com/tuneinsight/lattigo/v4/utils"
)

var nbParties = int(5)

var flagParamString = flag.String("params", "", "specify the test cryptographic parameters as a JSON string. Overrides -short and -long.")

func testString(opname string, tc *testContext) string {
	return fmt.Sprintf("%s/LogN=%d/logQP=%d/parties=%d", opname, tc.params.LogN(), tc.params.LogQP(), tc.nParties())
}

// TestParams is a set of test parameters for the correctness of the rlwe package.
var TestParams = []rlwe.ParametersLiteral{
	rlwe.TestPN10QP27,
	rlwe.TestPN11QP54,
	rlwe.TestPN12QP109,
	rlwe.TestPN13QP218,
	rlwe.TestPN14QP438,
	rlwe.TestPN15QP880,
	rlwe.TestPN16QP240,
	rlwe.TestPN17QP360}

type testContext struct {
	params         rlwe.Parameters
	kgen           rlwe.KeyGenerator
	skShares       []*rlwe.SecretKey
	skIdeal        *rlwe.SecretKey
	uniformSampler *ring.UniformSampler
	crs            utils.PRNG
}

func newTestContext(params rlwe.Parameters) *testContext {

	levelQ, levelP := params.QCount()-1, params.PCount()-1

	kgen := rlwe.NewKeyGenerator(params)
	skShares := make([]*rlwe.SecretKey, nbParties)
	skIdeal := rlwe.NewSecretKey(params)
	for i := range skShares {
		skShares[i] = kgen.GenSecretKey()
		params.RingQP().AddLvl(levelQ, levelP, skIdeal.Value, skShares[i].Value, skIdeal.Value)
	}

	prng, _ := utils.NewKeyedPRNG([]byte{'t', 'e', 's', 't'})
	unifSampler := ring.NewUniformSampler(prng, params.RingQ())

	return &testContext{params, kgen, skShares, skIdeal, unifSampler, prng}
}

func (tc testContext) nParties() int {
	return len(tc.skShares)
}

func TestDRLWE(t *testing.T) {

	var err error

	defaultParams := TestParams // the default test runs for ring degree N=2^12, 2^13, 2^14, 2^15
	if testing.Short() {
		defaultParams = TestParams[:2] // the short test suite runs for ring degree N=2^12, 2^13
	}

	if *flagParamString != "" {
		var jsonParams rlwe.ParametersLiteral
		if err = json.Unmarshal([]byte(*flagParamString), &jsonParams); err != nil {
			t.Fatal(err)
		}
		defaultParams = []rlwe.ParametersLiteral{jsonParams} // the custom test suite reads the parameters from the -params flag
	}

	for _, defaultParam := range defaultParams {
		var params rlwe.Parameters
		if params, err = rlwe.NewParametersFromLiteral(defaultParam); err != nil {
			t.Fatal(err)
		}

		testCtx := newTestContext(params)

		for _, testSet := range []func(tc *testContext, t *testing.T){
			testPublicKeyGen,
			testRelinKeyGen,
			testRotKeyGen,
			testKeySwitching,
			testPublicKeySwitching,
			testMarshalling,
			testThreshold,
		} {
			testSet(testCtx, t)
			runtime.GC()
		}
	}
}

func testPublicKeyGen(testCtx *testContext, t *testing.T) {

	params := testCtx.params

	t.Run(testString("PublicKeyGen", testCtx), func(t *testing.T) {

		ckg := make([]*CKGProtocol, nbParties)
		for i := range ckg {
			if i == 0 {
				ckg[i] = NewCKGProtocol(params)
			} else {
				ckg[i] = ckg[0].ShallowCopy()
			}
		}

		shares := make([]*CKGShare, nbParties)
		for i := range shares {
			shares[i] = ckg[i].AllocateShare()
		}

		crp := ckg[0].SampleCRP(testCtx.crs)

		for i := range shares {
			ckg[i].GenShare(testCtx.skShares[i], crp, shares[i])
		}

		for i := 1; i < nbParties; i++ {
			ckg[0].AggregateShares(shares[0], shares[i], shares[0])
		}

		pk := rlwe.NewPublicKey(params)
		ckg[0].GenPublicKey(shares[0], crp, pk)

		log2Bound := bits.Len64(3 * params.NoiseBound() * uint64(params.N()))
		require.True(t, rlwe.PublicKeyIsCorrect(pk, testCtx.skIdeal, params, log2Bound))
	})
}

func testKeySwitching(testCtx *testContext, t *testing.T) {

	params := testCtx.params
	ringQ := params.RingQ()
	ringQP := params.RingQP()
	levelQ, levelP := params.QCount()-1, params.PCount()-1
	t.Run(testString("KeySwitching", testCtx), func(t *testing.T) {

		cks := make([]*CKSProtocol, nbParties)

		sigmaSmudging := 8 * rlwe.DefaultSigma

		for i := range cks {
			if i == 0 {
				cks[i] = NewCKSProtocol(params, sigmaSmudging)
			} else {
				cks[i] = cks[0].ShallowCopy()
			}
		}

		skout := make([]*rlwe.SecretKey, nbParties)
		skOutIdeal := rlwe.NewSecretKey(params)
		for i := range skout {
			skout[i] = testCtx.kgen.GenSecretKey()
			ringQP.AddLvl(levelQ, levelP, skOutIdeal.Value, skout[i].Value, skOutIdeal.Value)
		}

		ciphertext := &rlwe.Ciphertext{Value: []*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly()}}
		testCtx.uniformSampler.Read(ciphertext.Value[1])
		ringQ.MulCoeffsMontgomeryAndSub(ciphertext.Value[1], testCtx.skIdeal.Value.Q, ciphertext.Value[0])
		ciphertext.Value[0].IsNTT = true
		ciphertext.Value[1].IsNTT = true

		shares := make([]*CKSShare, nbParties)
		for i := range shares {
			shares[i] = cks[i].AllocateShare(ciphertext.Level())
		}

		for i := range shares {
			cks[i].GenShare(testCtx.skShares[i], skout[i], ciphertext.Value[1], shares[i])
		}

		for i := 1; i < nbParties; i++ {
			cks[i].AggregateShares(shares[0], shares[i], shares[0])
		}

		ksCiphertext := &rlwe.Ciphertext{Value: []*ring.Poly{params.RingQ().NewPoly(), params.RingQ().NewPoly()}}

		cks[0].KeySwitch(ciphertext, shares[0], ksCiphertext)

		// [-as + e] + [as]
		ringQ.MulCoeffsMontgomeryAndAdd(ksCiphertext.Value[1], skOutIdeal.Value.Q, ksCiphertext.Value[0])
		ringQ.InvNTT(ksCiphertext.Value[0], ksCiphertext.Value[0])

		log2Bound := bits.Len64(uint64(nbParties) * uint64(math.Floor(sigmaSmudging*6)) * uint64(params.N()))
		require.GreaterOrEqual(t, log2Bound, ringQ.Log2OfInnerSum(ksCiphertext.Value[0].Level(), ksCiphertext.Value[0]))

	})
}

func testPublicKeySwitching(testCtx *testContext, t *testing.T) {

	params := testCtx.params
	ringQ := params.RingQ()

	t.Run(testString("PublicKeySwitching", testCtx), func(t *testing.T) {

		skOut, pkOut := testCtx.kgen.GenKeyPair()

		sigmaSmudging := 8 * rlwe.DefaultSigma

		pcks := make([]*PCKSProtocol, nbParties)
		for i := range pcks {
			if i == 0 {
				pcks[i] = NewPCKSProtocol(params, sigmaSmudging)
			} else {
				pcks[i] = pcks[0].ShallowCopy()
			}
		}

		ciphertext := &rlwe.Ciphertext{Value: []*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly()}}
		testCtx.uniformSampler.Read(ciphertext.Value[1])
		ringQ.MulCoeffsMontgomeryAndSub(ciphertext.Value[1], testCtx.skIdeal.Value.Q, ciphertext.Value[0])
		ciphertext.Value[0].IsNTT = true
		ciphertext.Value[1].IsNTT = true

		shares := make([]*PCKSShare, nbParties)
		for i := range shares {
			shares[i] = pcks[i].AllocateShare(ciphertext.Level())
		}

		for i := range shares {
			pcks[i].GenShare(testCtx.skShares[i], pkOut, ciphertext.Value[1], shares[i])
		}

		for i := 1; i < nbParties; i++ {
			pcks[0].AggregateShares(shares[0], shares[i], shares[0])
		}

		ksCiphertext := &rlwe.Ciphertext{Value: []*ring.Poly{params.RingQ().NewPoly(), params.RingQ().NewPoly()}}

		pcks[0].KeySwitch(ciphertext, shares[0], ksCiphertext)

		// [-as + e] + [as]
		ringQ.MulCoeffsMontgomeryAndAdd(ksCiphertext.Value[1], skOut.Value.Q, ksCiphertext.Value[0])
		ringQ.InvNTT(ksCiphertext.Value[0], ksCiphertext.Value[0])

		log2Bound := bits.Len64(uint64(nbParties) * uint64(math.Floor(sigmaSmudging*6)) * uint64(params.N()))

		require.GreaterOrEqual(t, log2Bound+5, ringQ.Log2OfInnerSum(ksCiphertext.Value[0].Level(), ksCiphertext.Value[0]))

	})
}

func testRelinKeyGen(testCtx *testContext, t *testing.T) {
	params := testCtx.params
	levelQ, levelP := params.QCount()-1, params.PCount()-1

	t.Run(testString("RelinKeyGen", testCtx), func(t *testing.T) {

		rkg := make([]*RKGProtocol, nbParties)

		for i := range rkg {
			if i == 0 {
				rkg[i] = NewRKGProtocol(params)
			} else {
				rkg[i] = rkg[0].ShallowCopy()
			}
		}

		ephSk := make([]*rlwe.SecretKey, nbParties)
		share1 := make([]*RKGShare, nbParties)
		share2 := make([]*RKGShare, nbParties)

		for i := range rkg {
			ephSk[i], share1[i], share2[i] = rkg[i].AllocateShare()
		}

		crp := rkg[0].SampleCRP(testCtx.crs)
		for i := range rkg {
			rkg[i].GenShareRoundOne(testCtx.skShares[i], crp, ephSk[i], share1[i])
		}

		for i := 1; i < nbParties; i++ {
			rkg[0].AggregateShares(share1[0], share1[i], share1[0])
		}

		for i := range rkg {
			rkg[i].GenShareRoundTwo(ephSk[i], testCtx.skShares[i], share1[0], share2[i])
		}

		for i := 1; i < nbParties; i++ {
			rkg[0].AggregateShares(share2[0], share2[i], share2[0])
		}

		rlk := rlwe.NewRelinKey(params, 2)
		rkg[0].GenRelinearizationKey(share1[0], share2[0], rlk)
		swk := rlk.Keys[0]

		decompSize := params.DecompPw2(levelQ, levelP) * params.DecompRNS(levelQ, levelP)
		log2Bound := bits.Len64(uint64(params.N() * decompSize * (params.N()*3*int(params.NoiseBound()) + 2*3*int(params.NoiseBound()) + params.N()*3)))

		require.True(t, rlwe.RelinearizationKeyIsCorrect(swk, testCtx.skIdeal, params, log2Bound))
	})
}

func testRotKeyGen(testCtx *testContext, t *testing.T) {

	params := testCtx.params
	levelQ, levelP := params.QCount()-1, params.PCount()-1

	t.Run(testString("RotKeyGen", testCtx), func(t *testing.T) {

		rtg := make([]*RTGProtocol, nbParties)
		for i := range rtg {
			if i == 0 {
				rtg[i] = NewRTGProtocol(params)
			} else {
				rtg[i] = rtg[0].ShallowCopy()
			}
		}

		shares := make([]*RTGShare, nbParties)
		for i := range shares {
			shares[i] = rtg[i].AllocateShare()
		}

		crp := rtg[0].SampleCRP(testCtx.crs)

		galEl := params.GaloisElementForRowRotation()

		for i := range shares {
			rtg[i].GenShare(testCtx.skShares[i], galEl, crp, shares[i])
		}

		for i := 1; i < nbParties; i++ {
			rtg[0].AggregateShares(shares[0], shares[i], shares[0])
		}

		rotKeySet := rlwe.NewRotationKeySet(params, []uint64{galEl})
		rtg[0].GenRotationKey(shares[0], crp, rotKeySet.Keys[galEl])

		decompSize := params.DecompPw2(levelQ, levelP) * params.DecompRNS(levelQ, levelP)
		log2Bound := bits.Len64(uint64(params.N() * decompSize * (params.N()*3*int(params.NoiseBound()) + 2*3*int(params.NoiseBound()) + params.N()*3)))

		require.True(t, rlwe.RotationKeyIsCorrect(rotKeySet.Keys[galEl], galEl, testCtx.skIdeal, params, log2Bound))
	})
}

func testMarshalling(testCtx *testContext, t *testing.T) {

	params := testCtx.params

	ciphertext := &rlwe.Ciphertext{Value: []*ring.Poly{params.RingQ().NewPoly(), params.RingQ().NewPoly()}}
	testCtx.uniformSampler.Read(ciphertext.Value[0])
	testCtx.uniformSampler.Read(ciphertext.Value[1])

	t.Run(testString("Marshalling/CKG", testCtx), func(t *testing.T) {
		ckg := NewCKGProtocol(testCtx.params)
		KeyGenShareBefore := ckg.AllocateShare()
		crs := ckg.SampleCRP(testCtx.crs)

		ckg.GenShare(testCtx.skShares[0], crs, KeyGenShareBefore)
		//now we marshall it
		data, err := KeyGenShareBefore.MarshalBinary()

		if err != nil {
			t.Error("Could not marshal the CKGShare : ", err)
		}

		KeyGenShareAfter := new(CKGShare)
		err = KeyGenShareAfter.UnmarshalBinary(data)
		if err != nil {
			t.Error("Could not unmarshal the CKGShare : ", err)
		}

		//comparing the results
		require.Equal(t, KeyGenShareBefore.Value.Q.N(), KeyGenShareAfter.Value.Q.N())
		require.Equal(t, KeyGenShareBefore.Value.Q.Level(), KeyGenShareAfter.Value.Q.Level())
		require.Equal(t, KeyGenShareAfter.Value.Q.Coeffs, KeyGenShareBefore.Value.Q.Coeffs)

		if params.RingP() != nil {
			require.Equal(t, KeyGenShareBefore.Value.P.N(), KeyGenShareAfter.Value.P.N())
			require.Equal(t, KeyGenShareBefore.Value.P.Level(), KeyGenShareAfter.Value.P.Level())
			require.Equal(t, KeyGenShareAfter.Value.P.Coeffs, KeyGenShareBefore.Value.P.Coeffs)
		}
	})

	t.Run(testString("Marshalling/PCKS", testCtx), func(t *testing.T) {
		//Check marshalling for the PCKS

		KeySwitchProtocol := NewPCKSProtocol(testCtx.params, testCtx.params.Sigma())
		SwitchShare := KeySwitchProtocol.AllocateShare(ciphertext.Level())
		_, pkOut := testCtx.kgen.GenKeyPair()
		KeySwitchProtocol.GenShare(testCtx.skShares[0], pkOut, ciphertext.Value[1], SwitchShare)

		data, err := SwitchShare.MarshalBinary()
		require.NoError(t, err)

		SwitchShareReceiver := new(PCKSShare)
		err = SwitchShareReceiver.UnmarshalBinary(data)
		require.NoError(t, err)

		require.Equal(t, SwitchShare.Value[0].N(), SwitchShareReceiver.Value[0].N())
		require.Equal(t, SwitchShare.Value[1].N(), SwitchShareReceiver.Value[1].N())
		require.Equal(t, SwitchShare.Value[0].Level(), SwitchShareReceiver.Value[0].Level())
		require.Equal(t, SwitchShare.Value[1].Level(), SwitchShareReceiver.Value[1].Level())
		require.Equal(t, SwitchShare.Value[0].Coeffs, SwitchShareReceiver.Value[0].Coeffs)
		require.Equal(t, SwitchShare.Value[1].Coeffs, SwitchShareReceiver.Value[1].Coeffs)
	})

	t.Run(testString("Marshalling/CKS", testCtx), func(t *testing.T) {

		//Now for CKSShare ~ its similar to PKSShare
		cksp := NewCKSProtocol(testCtx.params, testCtx.params.Sigma())
		cksshare := cksp.AllocateShare(ciphertext.Level())
		cksp.GenShare(testCtx.skShares[0], testCtx.skShares[1], ciphertext.Value[1], cksshare)

		data, err := cksshare.MarshalBinary()
		require.NoError(t, err)
		cksshareAfter := new(CKSShare)
		err = cksshareAfter.UnmarshalBinary(data)
		require.NoError(t, err)

		//now compare both shares.

		require.Equal(t, cksshare.Value.N(), cksshareAfter.Value.N())
		require.Equal(t, cksshare.Value.Level(), cksshareAfter.Value.Level())

		require.Equal(t, cksshare.Value.Coeffs, cksshareAfter.Value.Coeffs)
	})

	t.Run(testString("Marshalling/RKG", testCtx), func(t *testing.T) {

		RKGProtocol := NewRKGProtocol(params)

		ephSk0, share10, _ := RKGProtocol.AllocateShare()

		crp := RKGProtocol.SampleCRP(testCtx.crs)

		RKGProtocol.GenShareRoundOne(testCtx.skShares[0], crp, ephSk0, share10)

		data, err := share10.MarshalBinary()
		require.NoError(t, err)

		rkgShare := new(RKGShare)
		err = rkgShare.UnmarshalBinary(data)
		require.NoError(t, err)

		require.Equal(t, len(rkgShare.Value), len(share10.Value))
		for i := range share10.Value {
			for j, val := range share10.Value[i] {

				require.Equal(t, len(rkgShare.Value[i][j][0].Q.Coeffs), len(val[0].Q.Coeffs))
				require.Equal(t, rkgShare.Value[i][j][0].Q.Coeffs, val[0].Q.Coeffs)
				require.Equal(t, len(rkgShare.Value[i][j][1].Q.Coeffs), len(val[1].Q.Coeffs))
				require.Equal(t, rkgShare.Value[i][j][1].Q.Coeffs, val[1].Q.Coeffs)

				if params.PCount() != 0 {
					require.Equal(t, len(rkgShare.Value[i][j][0].P.Coeffs), len(val[0].P.Coeffs))
					require.Equal(t, rkgShare.Value[i][j][0].P.Coeffs, val[0].P.Coeffs)
					require.Equal(t, len(rkgShare.Value[i][j][1].P.Coeffs), len(val[1].P.Coeffs))
					require.Equal(t, rkgShare.Value[i][j][1].P.Coeffs, val[1].P.Coeffs)
				}
			}
		}
	})

	t.Run(testString("Marshalling/RTG", testCtx), func(t *testing.T) {

		galEl := testCtx.params.GaloisElementForColumnRotationBy(64)

		rtg := NewRTGProtocol(testCtx.params)
		rtgShare := rtg.AllocateShare()

		crp := rtg.SampleCRP(testCtx.crs)

		rtg.GenShare(testCtx.skShares[0], galEl, crp, rtgShare)

		data, err := rtgShare.MarshalBinary()
		require.NoError(t, err)

		resRTGShare := new(RTGShare)
		err = resRTGShare.UnmarshalBinary(data)
		require.NoError(t, err)

		require.Equal(t, len(resRTGShare.Value), len(rtgShare.Value))

		for i := range rtgShare.Value {
			for j, val := range rtgShare.Value[i] {
				require.Equal(t, len(resRTGShare.Value[i][j].Q.Coeffs), len(val.Q.Coeffs))
				require.Equal(t, resRTGShare.Value[i][j].Q.Coeffs, val.Q.Coeffs)

				if params.PCount() != 0 {
					require.Equal(t, len(resRTGShare.Value[i][j].P.Coeffs), len(val.P.Coeffs))
					require.Equal(t, resRTGShare.Value[i][j].P.Coeffs, val.P.Coeffs)
				}
			}
		}
	})
}

func testThreshold(tc *testContext, t *testing.T) {
	sk0Shards := tc.skShares

	for _, threshold := range []int{tc.nParties() / 4, tc.nParties() / 2, tc.nParties() - 1} {
		t.Run(testString("Threshold", tc)+fmt.Sprintf("/threshold=%d", threshold), func(t *testing.T) {

			type Party struct {
				*Thresholdizer
				*Combiner
				gen  *ShamirPolynomial
				sk   *rlwe.SecretKey
				tsks *ShamirSecretShare
				tsk  *rlwe.SecretKey
				tpk  ShamirPublicPoint
			}

			P := make([]*Party, tc.nParties())
			shamirPks := make([]ShamirPublicPoint, tc.nParties())
			for i := 0; i < tc.nParties(); i++ {
				p := new(Party)
				p.Thresholdizer = NewThresholdizer(tc.params)
				p.sk = sk0Shards[i]
				p.tsk = rlwe.NewSecretKey(tc.params)
				p.tpk = ShamirPublicPoint(i + 1)
				p.tsks = p.Thresholdizer.AllocateThresholdSecretShare()
				P[i] = p
				shamirPks[i] = p.tpk
			}

			for _, pi := range P {
				pi.Combiner = NewCombiner(tc.params, pi.tpk, shamirPks, threshold)
			}

			shares := make(map[*Party]map[*Party]*ShamirSecretShare, tc.nParties())
			var err error
			// Every party generates a share for every other party
			for _, pi := range P {

				pi.gen, err = pi.Thresholdizer.GenShamirPolynomial(threshold, pi.sk)
				if err != nil {
					t.Error(err)
				}

				shares[pi] = make(map[*Party]*ShamirSecretShare)
				for _, pj := range P {
					shares[pi][pj] = pi.Thresholdizer.AllocateThresholdSecretShare()
					pi.Thresholdizer.GenShamirSecretShare(pj.tpk, pi.gen, shares[pi][pj])
				}
			}

			//Each party aggregates what it has received into a secret key
			for _, pi := range P {
				for _, pj := range P {
					pi.Thresholdizer.AggregateShares(pi.tsks, shares[pj][pi], pi.tsks)
				}
			}

			// Determining which parties are active. In a distributed context, a party
			// would receive the ids of active players and retrieve (or compute) the corresponding keys.
			activeParties := P[:threshold]
			activeShamirPks := make([]ShamirPublicPoint, threshold)
			for i, p := range activeParties {
				activeShamirPks[i] = p.tpk
			}

			// Combining
			// Slow because each party has to generate its public key on-the-fly. In
			// practice the public key could be precomputed from an id by parties during setup
			ringQP := tc.params.RingQP()
			levelQ, levelP := tc.params.QCount()-1, tc.params.PCount()-1
			recSk := rlwe.NewSecretKey(tc.params)
			for _, pi := range activeParties {
				pi.Combiner.GenAdditiveShare(activeShamirPks, pi.tpk, pi.tsks, pi.tsk)
				ringQP.AddLvl(levelQ, levelP, pi.tsk.Value, recSk.Value, recSk.Value)
			}

			require.True(t, tc.skIdeal.Value.Equals(recSk.Value)) // reconstructed key should match the ideal sk
		})
	}
}
