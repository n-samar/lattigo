package bgv

import (
	"runtime"
	"testing"
)

func BenchmarkBGV(b *testing.B) {

	var err error

	for _, p := range TestParams[:] {

		var params Parameters
		if params, err = NewParametersFromLiteral(p); err != nil {
			b.Error(err)
			b.Fail()
		}

		var tc *testContext
		if tc, err = genTestParams(params); err != nil {
			b.Error(err)
			b.Fail()
		}

		for _, testSet := range []func(tc *testContext, b *testing.B){
			benchEncoder,
			benchEvaluator,
		} {
			testSet(tc, b)
			runtime.GC()
		}
	}
}

func benchEncoder(tc *testContext, b *testing.B) {

	poly := tc.uSampler.ReadNew()

	tc.params.RingT().Reduce(poly, poly)

	coeffsUint64 := poly.Coeffs[0]

	coeffsInt64 := make([]int64, len(coeffsUint64))
	for i := range coeffsUint64 {
		coeffsInt64[i] = int64(coeffsUint64[i])
	}

	encoder := tc.encoder

	for _, lvl := range tc.testLevel {
		plaintext := NewPlaintext(tc.params, lvl, 1)
		b.Run(testString("Encoder/Encode/Uint", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoder.Encode(coeffsUint64, plaintext)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		plaintext := NewPlaintext(tc.params, lvl, 1)
		b.Run(testString("Encoder/Encode/Int", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoder.Encode(coeffsInt64, plaintext)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		plaintext := NewPlaintext(tc.params, lvl, 1)
		b.Run(testString("Encoder/Decode/Uint", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoder.DecodeUint(plaintext, coeffsUint64)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		plaintext := NewPlaintext(tc.params, lvl, 1)
		b.Run(testString("Encoder/Decode/Int", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				encoder.DecodeInt(plaintext, coeffsInt64)
			}
		})
	}
}

func benchEvaluator(tc *testContext, b *testing.B) {

	eval := tc.evaluator
	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		_, _, ciphertext1 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/Add/op0=ct/op1=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Add(ciphertext0, ciphertext1, ciphertext0)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		_, plaintext1, _ := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/Add/op0=ct/op1=pt", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Add(ciphertext0, plaintext1, ciphertext0)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/AddScalar/op0=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.AddScalar(ciphertext0, 65535, ciphertext0)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/MulScalar/op0=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.MulScalar(ciphertext0, 65535, ciphertext0)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		_, _, ciphertext1 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/MulScalarAndAdd/op0=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.MulScalarAndAdd(ciphertext0, 65535, ciphertext1)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		_, _, ciphertext1 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		receiver := NewCiphertext(tc.params, 2, lvl, 1)
		b.Run(testString("Evaluator/Mul/op0=ct/op1=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Mul(ciphertext0, ciphertext1, receiver)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		_, plaintext1, _ := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/Mul/op0=ct/op1=pt", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Mul(ciphertext0, plaintext1, ciphertext0)
			}
		})
	}

	for _, lvl := range tc.testLevel {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		_, _, ciphertext1 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		b.Run(testString("Evaluator/MulRelin/op0=ct/op1=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.MulRelin(ciphertext0, ciphertext1, ciphertext0)
			}
		})
	}

	for _, lvl := range tc.testLevel[1:] {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		receiver := NewCiphertext(tc.params, 1, lvl-1, 1)
		b.Run(testString("Evaluator/Rescale/op0=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.Rescale(ciphertext0, receiver)
			}
		})
	}

	for _, lvl := range tc.testLevel[1:] {
		_, _, ciphertext0 := newTestVectorsLvl(lvl, 1, tc, tc.encryptorPk)
		receiver := NewCiphertext(tc.params, 1, lvl-1, 1)
		b.Run(testString("Evaluator/Rescale(OLD)/op0=ct", tc.params, lvl), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				eval.(*evaluator).rescaleOriginal(ciphertext0, receiver)
			}
		})
	}
}
