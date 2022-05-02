package bgv

import (
	"fmt"
	"math/big"
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
			testParameters,
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

func newTestVectorsLvl(level int, scale uint64, tc *testContext, encryptor Encryptor) (coeffs *ring.Poly, plaintext *Plaintext, ciphertext *Ciphertext) {
	coeffs = tc.uSampler.ReadNew()
	plaintext = NewPlaintext(tc.params, level, scale)
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

func testParameters(tc *testContext, t *testing.T) {

	t.Run("Parameters/NewParameters", func(t *testing.T) {
		params, err := NewParametersFromLiteral(ParametersLiteral{
			ParametersLiteral: rlwe.ParametersLiteral{
				LogN: 4,
				LogQ: []int{60, 60},
				LogP: []int{60},
			},
			T: 0x10001,
		})
		require.NoError(t, err)
		require.Equal(t, ring.Standard, params.RingType())  // Default ring type should be standard
		require.Equal(t, rlwe.DefaultSigma, params.Sigma()) // Default error std should be rlwe.DefaultSigma
	})

	t.Run("Parameters/CopyNew", func(t *testing.T) {
		params1, params2 := tc.params.CopyNew(), tc.params.CopyNew()
		require.True(t, params1.Equals(tc.params) && params2.Equals(tc.params))
		params1.ringT, _ = ring.NewRing(params1.N(), []uint64{0x40002001})
		require.False(t, params1.Equals(tc.params))
		require.True(t, params2.Equals(tc.params))
	})
}

func testEncoder(tc *testContext, t *testing.T) {

	for _, lvl := range tc.testLevel {
		t.Run(testString("Encoder/Encode&Decode/Uint", tc.params, lvl), func(t *testing.T) {
			values, plaintext, _ := newTestVectorsLvl(lvl, 1, tc, nil)
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
			values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
		})
	}

	for _, lvl := range tc.testLevel {
		t.Run(testString("Encoder/encryptorSk", tc.params, lvl), func(t *testing.T) {
			values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)
			verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
		})
	}
}

func testEvaluator(tc *testContext, t *testing.T) {

	t.Run("Evaluator", func(t *testing.T) {

		for _, lvl := range tc.testLevel {
			t.Run(testString("AddNew/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				ciphertext2 := tc.evaluator.AddNew(ciphertext0, ciphertext1)
				tc.ringT.Add(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext2, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Add/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				tc.evaluator.Add(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Add(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Add/op0=ct/op2=pt", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, plaintext, _ := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, plaintext.Scale)

				tc.evaluator.Add(ciphertext0, plaintext, ciphertext0)
				tc.ringT.Add(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Add/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				tc.evaluator.Add(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Add(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("SubNew/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				ciphertext0 = tc.evaluator.SubNew(ciphertext0, ciphertext1)
				tc.ringT.Sub(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Sub/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				tc.evaluator.Sub(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Sub(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Sub/op0=ct/op2=pt", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, plaintext, _ := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, plaintext.Scale)

				tc.evaluator.Sub(ciphertext0, plaintext, ciphertext0)
				tc.ringT.Sub(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Sub/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				tc.evaluator.Sub(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.Sub(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Neg/op0=ct", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)

				tc.evaluator.Neg(ciphertext, ciphertext)
				tc.ringT.Neg(values, values)
				tc.ringT.Reduce(values, values)

				verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("NegNew/op0=ct", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)

				ciphertext = tc.evaluator.NegNew(ciphertext)
				tc.ringT.Neg(values, values)
				tc.ringT.Reduce(values, values)

				verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("AddScalar/op0=ct", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)

				scalar := tc.params.T() >> 1

				tc.evaluator.AddScalar(ciphertext, scalar, ciphertext)
				tc.ringT.AddScalar(values, scalar, values)

				verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("AddScalarNew/op0=ct", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext.Scale, 1)

				scalar := tc.params.T() >> 1

				ciphertext = tc.evaluator.AddScalarNew(ciphertext, scalar)
				tc.ringT.AddScalar(values, scalar, values)

				verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("MulScalar/op0=ct", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)

				scalar := tc.params.T() >> 1

				tc.evaluator.MulScalar(ciphertext, scalar, ciphertext)
				tc.ringT.MulScalar(values, scalar, values)

				verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("MulScalarNew/op0=ct", tc.params, lvl), func(t *testing.T) {

				values, _, ciphertext := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)

				scalar := tc.params.T() >> 1

				ciphertext = tc.evaluator.MulScalarNew(ciphertext, scalar)
				tc.ringT.MulScalar(values, scalar, values)

				verifyTestVectors(tc, tc.decryptor, values, ciphertext, t)
			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("MulScalarAndAdd/op0=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				scalar := tc.params.T() >> 1

				tc.evaluator.MulScalarAndAdd(ciphertext0, scalar, ciphertext1)
				tc.ringT.MulScalarAndAdd(values0, scalar, values1)

				verifyTestVectors(tc, tc.decryptor, values1, ciphertext1, t)
			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Mul/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				tc.evaluator.Mul(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.MulCoeffs(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("MulRelin/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 3, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)

				tc.evaluator.MulRelin(ciphertext0, ciphertext1, ciphertext0)
				tc.ringT.MulCoeffs(values0, values1, values0)

				verifyTestVectors(tc, tc.decryptor, values0, ciphertext0, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("MulAndAdd/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 2, tc, tc.encryptorSk)
				values2, _, ciphertext2 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)
				require.NotEqual(t, ciphertext0.Scale, ciphertext2.Scale)

				tc.evaluator.MulAndAdd(ciphertext0, ciphertext1, ciphertext2)
				tc.ringT.MulCoeffsAndAdd(values0, values1, values2)

				verifyTestVectors(tc, tc.decryptor, values2, ciphertext2, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("MulRelinAndAdd/op0=ct/op2=ct", tc.params, lvl), func(t *testing.T) {

				values0, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorSk)
				values1, _, ciphertext1 := newTestVectorsLvl(lvl, 2, tc, tc.encryptorSk)
				values2, _, ciphertext2 := newTestVectorsLvl(lvl, 7, tc, tc.encryptorSk)

				require.NotEqual(t, ciphertext0.Scale, ciphertext1.Scale)
				require.NotEqual(t, ciphertext0.Scale, ciphertext2.Scale)

				tc.evaluator.MulRelinAndAdd(ciphertext0, ciphertext1, ciphertext2)
				tc.ringT.MulCoeffsAndAdd(values0, values1, values2)

				verifyTestVectors(tc, tc.decryptor, values2, ciphertext2, t)

			})
		}

		for _, lvl := range tc.testLevel {
			t.Run(testString("Rescale", tc.params, lvl), func(t *testing.T) {

				ringQ := tc.params.RingQ()

				values, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)

				if lvl != 0 {

					_, _, someMoreError := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)

					ringQ.MulScalar(someMoreError.Value[0], tc.params.T(), someMoreError.Value[0])
					ringQ.MulScalar(someMoreError.Value[1], tc.params.T(), someMoreError.Value[1])

					ringQ.Add(ciphertext0.Value[0], someMoreError.Value[0], ciphertext0.Value[0])
					ringQ.Add(ciphertext0.Value[1], someMoreError.Value[1], ciphertext0.Value[1])

					// Records the sum of the error
					coeffsBigint := make([]*big.Int, ringQ.N)
					for i := range coeffsBigint {
						coeffsBigint[i] = new(big.Int)
					}

					TBig := tc.params.RingT().ModulusAtLevel[0]

					plaintext := NewPlaintext(tc.params, lvl, 0)

					tc.decryptor.Decrypt(ciphertext0, plaintext)
					ringQ.InvNTT(plaintext.Value, plaintext.Value)
					ringQ.PolyToBigintCenteredLvl(lvl, plaintext.Value, 1, coeffsBigint)
					for i := range coeffsBigint {
						ring.DivRound(coeffsBigint[i], TBig, coeffsBigint[i])
					}
					varErr, _, _ := errorStats(coeffsBigint)

					ciphertext1 := ciphertext0.CopyNew()

					require.Nil(t, tc.evaluator.Rescale(ciphertext0, ciphertext0))
					require.Nil(t, tc.evaluator.(*evaluator).rescaleOriginal(ciphertext1, ciphertext1))

					verifyTestVectors(tc, tc.decryptor, values, ciphertext0, t)
					verifyTestVectors(tc, tc.decryptor, values, ciphertext1, t)

					tc.decryptor.Decrypt(ciphertext0, plaintext)
					ringQ.InvNTTLvl(lvl-1, plaintext.Value, plaintext.Value)
					ringQ.PolyToBigintCenteredLvl(lvl-1, plaintext.Value, 1, coeffsBigint)
					for i := range coeffsBigint {
						ring.DivRound(coeffsBigint[i], TBig, coeffsBigint[i])
					}
					varErrNewRescale, _, _ := errorStats(coeffsBigint)

					tc.decryptor.Decrypt(ciphertext1, plaintext)
					ringQ.InvNTTLvl(lvl-1, plaintext.Value, plaintext.Value)
					ringQ.PolyToBigintCenteredLvl(lvl-1, plaintext.Value, 1, coeffsBigint)
					for i := range coeffsBigint {
						ring.DivRound(coeffsBigint[i], TBig, coeffsBigint[i])
					}
					varErrOldRescale, _, _ := errorStats(coeffsBigint)

					t.Logf("VarErr (before): %f\n", varErr)
					t.Logf("VarErr (after, with new rescale): %f\n", varErrNewRescale)
					t.Logf("VarErr (after, with old rescale): %f\n", varErrOldRescale)

				} else {
					require.NotNil(t, tc.evaluator.Rescale(ciphertext0, ciphertext0))
				}
			})
		}
	})
}

func errorStats(vec []*big.Int) (float64, float64, float64) {

	vecfloat := make([]*big.Float, len(vec))
	minErr := new(big.Float).SetFloat64(0)
	maxErr := new(big.Float).SetFloat64(0)
	tmp := new(big.Float)
	minErr.SetInt(vec[0])
	minErr.Abs(minErr)
	for i := range vec {
		vecfloat[i] = new(big.Float)
		vecfloat[i].SetInt(vec[i])

		tmp.Abs(vecfloat[i])

		if minErr.Cmp(tmp) == 1 {
			minErr.Set(tmp)
		}

		if maxErr.Cmp(tmp) == -1 {
			maxErr.Set(tmp)
		}
	}

	n := new(big.Float).SetFloat64(float64(len(vec)))

	mean := new(big.Float).SetFloat64(0)

	for _, c := range vecfloat {
		mean.Add(mean, c)
	}

	mean.Quo(mean, n)

	err := new(big.Float).SetFloat64(0)
	for _, c := range vecfloat {
		tmp.Sub(c, mean)
		tmp.Mul(tmp, tmp)
		err.Add(err, tmp)
	}

	err.Quo(err, n)
	err.Sqrt(err)

	x, _ := err.Float64()
	y, _ := minErr.Float64()
	z, _ := maxErr.Float64()

	return x, y, z

}
