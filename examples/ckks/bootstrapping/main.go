package main

import (
	"fmt"
	"math"

	"github.com/tuneinsight/lattigo/v3/ckks"
	"github.com/tuneinsight/lattigo/v3/ckks/bootstrapping"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
)

func main() {

	var err error

	var btp *bootstrapping.Bootstrapper
	var kgen rlwe.KeyGenerator
	var encoder ckks.Encoder
	var sk *rlwe.SecretKey
	var pk *rlwe.PublicKey
	var encryptor ckks.Encryptor
	var decryptor ckks.Decryptor
	var plaintext *ckks.Plaintext

	// Bootstrapping parameters
	// Two sets of four parameters each, DefaultParametersSparse and DefaultParametersDense,
	// (each index 0 to 3) ensuring 128 bit of security are available in
	// github.com/tuneinsight/lattigo/v3/ckks/bootstrapping/default_params.go
	//
	// LogSlots is hardcoded to 15 in the parameters, but can be changed from 1 to 15.
	// When changing LogSlots make sure that the number of levels allocated to CtS and StC is
	// smaller or equal to LogSlots.

	paramSet := bootstrapping.DefaultParametersSparse[0] // bootstrapping.DefaultParametersDense[0]
	ckksParams := paramSet.SchemeParams
	btpParams := paramSet.BootstrappingParams

	params, err := ckks.NewParametersFromLiteral(ckksParams)
	if err != nil {
		panic(err)
	}

	fmt.Println()
	fmt.Printf("CKKS parameters: logN = %d, logSlots = %d, H(%d; %d), logQP = %d, levels = %d, scale= 2^%f, sigma = %f \n", params.LogN(), params.LogSlots(), params.HammingWeight(), btpParams.EphemeralSecretWeight, params.LogQP(), params.QCount(), math.Log2(params.DefaultScale()), params.Sigma())

	// Scheme context and keys
	kgen = ckks.NewKeyGenerator(params)

	sk, pk = kgen.GenKeyPair()

	encoder = ckks.NewEncoder(params)
	decryptor = ckks.NewDecryptor(params, sk)
	encryptor = ckks.NewEncryptor(params, pk)

	fmt.Println()
	fmt.Println("Generating bootstrapping keys...")
	evk := bootstrapping.GenEvaluationKeys(btpParams, params, sk)
	fmt.Println("Done")

	if btp, err = bootstrapping.NewBootstrapper(params, btpParams, evk); err != nil {
		panic(err)
	}

	// Generate a random plaintext
	valuesWant := make([]complex128, params.Slots())
	for i := range valuesWant {
		valuesWant[i] = utils.RandComplex128(-1, 1)
	}

	plaintext = encoder.EncodeNew(valuesWant, params.MaxLevel(), params.DefaultScale(), params.LogSlots())

	// Encrypt
	ciphertext1 := encryptor.EncryptNew(plaintext)

	// Decrypt, print and compare with the plaintext values
	fmt.Println()
	fmt.Println("Precision of values vs. ciphertext")
	valuesTest1 := printDebug(params, ciphertext1, valuesWant, decryptor, encoder)

	// Bootstrap the ciphertext (homomorphic re-encryption)
	// It takes a ciphertext at level 0 (if not at level 0, then it will reduce it to level 0)
	// and returns a ciphertext at level MaxLevel - k, where k is the depth of the bootstrapping circuit.
	// CAUTION: the scale of the ciphertext MUST be equal (or very close) to params.Scale
	// To equalize the scale, the function evaluator.SetScale(ciphertext, parameters.Scale) can be used at the expense of one level.
	fmt.Println()
	fmt.Println("Bootstrapping...")
	ciphertext2 := btp.Bootstrapp(ciphertext1)
	fmt.Println("Done")

	// Decrypt, print and compare with the plaintext values
	fmt.Println()
	fmt.Println("Precision of ciphertext vs. Bootstrapp(ciphertext)")
	printDebug(params, ciphertext2, valuesTest1, decryptor, encoder)
}

func printDebug(params ckks.Parameters, ciphertext *ckks.Ciphertext, valuesWant []complex128, decryptor ckks.Decryptor, encoder ckks.Encoder) (valuesTest []complex128) {

	valuesTest = encoder.Decode(decryptor.DecryptNew(ciphertext), params.LogSlots())

	fmt.Println()
	fmt.Printf("Level: %d (logQ = %d)\n", ciphertext.Level(), params.LogQLvl(ciphertext.Level()))
	fmt.Printf("Scale: 2^%f\n", math.Log2(ciphertext.Scale))
	fmt.Printf("ValuesTest: %6.10f %6.10f %6.10f %6.10f...\n", valuesTest[0], valuesTest[1], valuesTest[2], valuesTest[3])
	fmt.Printf("ValuesWant: %6.10f %6.10f %6.10f %6.10f...\n", valuesWant[0], valuesWant[1], valuesWant[2], valuesWant[3])

	precStats := ckks.GetPrecisionStats(params, encoder, nil, valuesWant, valuesTest, params.LogSlots(), 0)

	fmt.Println(precStats.String())
	fmt.Println()

	return
}
