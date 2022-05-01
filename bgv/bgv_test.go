package bgv

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"

	"github.com/stretchr/testify/require"
)

var (
	// TESTTCPrimeQN2Q1P is a set of test parameters where T is coprime with Q.
	TESTN14QP418 = ParametersLiteral{
		ParametersLiteral: rlwe.ParametersLiteral{
			LogN:  14,
			Q:     []uint64{0xffffffffffe8001, 0xffffffffffd8001, 0xffffffffffc0001, 0xffffffffff28001},
			P:     []uint64{0x1fffffffffe10001, 0x1fffffffffe00001},
			Sigma: rlwe.DefaultSigma,
		},
		T: 0x10001,
	}

	// TestParams is a set of test parameters for BFV ensuring 128 bit security in the classic setting.
	TestParams = []ParametersLiteral{TESTN14QP418}
)

func testString(opname string, p Parameters, lvl int) string {
	return fmt.Sprintf("%s/LogN=%d/logQP=%d/logT=%d/#Q=%d/#P=%d/lvl=%d", opname, p.LogN(), p.LogQP(), p.LogT(), p.QCount(), p.PCount(), lvl)
}

func TestBGV(t *testing.T) {

	var err error

	for _, p := range TestParams[:] {

		var params Parameters
		if params, err = NewParametersFromLiteral(p); err != nil {
			t.Error(err)
			t.Fail()
		}

		var tc *testContext
		if tc, err = genTestParams(params); err != nil {
			t.Error(err)
			t.Fail()
		}

		for _, testSet := range []func(tc *testContext, t *testing.T){
			testEncoder,
			testEncryptor,
			testEvaluator,
		} {
			testSet(tc, t)
			runtime.GC()
		}
	}
}

type testContext struct {
	params      Parameters
	ringQ       *ring.Ring
	ringT       *ring.Ring
	prng        utils.PRNG
	uSampler    *ring.UniformSampler
	encoder     Encoder
	kgen        rlwe.KeyGenerator
	sk          *rlwe.SecretKey
	pk          *rlwe.PublicKey
	rlk         *rlwe.RelinearizationKey
	encryptorPk Encryptor
	encryptorSk Encryptor
	decryptor   Decryptor
	evaluator   Evaluator
	testLevel   []int
}

func genTestParams(params Parameters) (tc *testContext, err error) {

	tc = new(testContext)
	tc.params = params

	if tc.prng, err = utils.NewPRNG(); err != nil {
		return nil, err
	}

	tc.ringQ = params.RingQ()
	tc.ringT = params.RingT()

	tc.uSampler = ring.NewUniformSampler(tc.prng, tc.ringT)
	tc.kgen = NewKeyGenerator(tc.params)
	tc.sk, tc.pk = tc.kgen.GenKeyPair()
	if params.PCount() != 0 {
		tc.rlk = tc.kgen.GenRelinearizationKey(tc.sk, 1)
	}

	tc.encoder = NewEncoder(tc.params)
	tc.encryptorPk = NewEncryptor(tc.params, tc.pk)
	tc.encryptorSk = NewEncryptor(tc.params, tc.sk)
	tc.decryptor = NewDecryptor(tc.params, tc.sk)
	tc.evaluator = NewEvaluator(tc.params, rlwe.EvaluationKey{Rlk: tc.rlk})

	tc.testLevel = []int{0, 3}

	return
}

func newTestVectorsLvl(level int, tc *testContext, encryptor Encryptor, t *testing.T) (coeffs *ring.Poly, plaintext *Plaintext, ciphertext *Ciphertext) {
	//coeffs = tc.uSampler.ReadNew()
	coeffs = &ring.Poly{
		Coeffs: make([][]uint64, 1),
	}
	coeffs.Coeffs[0] = make([]uint64, tc.params.RingQ().N)
	for i := range coeffs.Coeffs[0] {
		coeffs.Coeffs[0][i] = uint64(1)
	}

	plaintext = NewPlaintext(tc.params, level, 1)
	tc.encoder.Encode(coeffs.Coeffs[0], plaintext)
	if encryptor != nil {
		ciphertext = encryptor.EncryptNew(plaintext)
	}

	return coeffs, plaintext, ciphertext
}

func verifyTestVectors(tc *testContext, decryptor Decryptor, coeffs *ring.Poly, element Operand, t *testing.T) {

	var coeffsTest []uint64

	switch el := element.(type) {
	case *Plaintext:
		coeffsTest = tc.encoder.DecodeUintNew(el)
	case *Ciphertext:
		coeffsTest = tc.encoder.DecodeUintNew(decryptor.DecryptNew(el))
	default:
		t.Error("invalid test object to verify")
	}

	require.True(t, utils.EqualSliceUint64(coeffs.Coeffs[0], coeffsTest))
}

func testEncoder(tc *testContext, t *testing.T) {

	for _, lvl := range tc.testLevel {
		t.Run(testString("Encoder/Encode&Decode/Uint", tc.params, lvl), func(t *testing.T) {
			values, plaintext, _ := newTestVectorsLvl(lvl, tc, nil, t)
			verifyTestVectors(tc, nil, values, plaintext, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(testString("Encoder/Encode&Decode/Int", tc.params, lvl), func(t *testing.T) {

			T := tc.params.T()
			THalf := T >> 1
			coeffs := tc.uSampler.ReadNew()
			coeffsInt := make([]int64, len(coeffs.Coeffs[0]))
			for i, c := range coeffs.Coeffs[0] {
				c %= T
				if c >= THalf {
					coeffsInt[i] = -int64(T - c)
				} else {
					coeffsInt[i] = int64(c)
				}
			}

			plaintext := NewPlaintext(tc.params, lvl, 1)
			tc.encoder.Encode(coeffsInt, plaintext)
			require.True(t, utils.EqualSliceInt64(coeffsInt, tc.encoder.DecodeIntNew(plaintext)))
		})
	}
}

func testEncryptor(tc *testContext, t *testing.T) {

	for _, lvl := range tc.testLevel {
		t.Run(testString("Encoder/EncryptorPk", tc.params, lvl), func(t *testing.T) {
			values, _, ciphertext := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(testString("Encoder/EncryptorSk", tc.params, lvl), func(t *testing.T) {
			values, _, ciphertext := newTestVectorsLvl(lvl, tc, tc.encryptorSk, t)
			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
		})
	}
}

func testEvaluator(tc *testContext, t *testing.T) {

	t.Run("Evaluator", func(t *testing.T) {

		for _, lvl := range tc.testLevel {
			t.Run(testString("Evaluator/Add/op0=ct/op2=ct/scale=matche", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				tc.evaluator.Add(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Add(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Evaluator/Add/op0=ct/op2=ct/scale=mix", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				tc.ringQ.MulScalar(ciphertext0.Value[0], 7, ciphertext0.Value[0])
				tc.ringQ.MulScalar(ciphertext0.Value[1], 7, ciphertext0.Value[1])
				ciphertext0.Scale = (ciphertext0.Scale * 7) % tc.params.T()

				tc.ringQ.MulScalar(ciphertext1.Value[0], 9, ciphertext1.Value[0])
				tc.ringQ.MulScalar(ciphertext1.Value[1], 9, ciphertext1.Value[1])
				ciphertext1.Scale = (ciphertext1.Scale * 9) % tc.params.T()

				tc.evaluator.Add(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Add(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Evaluator/Sub", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				tc.evaluator.Sub(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Sub(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Evaluator/Sub/op0=ct/op2=ct/scale=mix", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				tc.ringQ.MulScalar(ciphertext0.Value[0], 7, ciphertext0.Value[0])
				tc.ringQ.MulScalar(ciphertext0.Value[1], 7, ciphertext0.Value[1])
				ciphertext0.Scale = (ciphertext0.Scale * 7) % tc.params.T()

				tc.ringQ.MulScalar(ciphertext1.Value[0], 9, ciphertext1.Value[0])
				tc.ringQ.MulScalar(ciphertext1.Value[1], 9, ciphertext1.Value[1])
				ciphertext1.Scale = (ciphertext1.Scale * 9) % tc.params.T()

				tc.evaluator.Sub(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Sub(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Evaluator/Mul/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				tc.evaluator.Mul(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.MulCoeffs(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Evaluator/MulRelin/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				tc.evaluator.MulRelin(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.MulCoeffs(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Rescale", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, tc, tc.encryptorPk, t)

				err := tc.evaluator.Rescale(ciphertext, ciphertext)

				if tc.params.MaxLevel() == 0 {
					require.NotNil(t, err)
				} else {
					verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
				}
			})
		}
	})
}
