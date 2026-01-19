package tle

import (
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

func TestCircuitCompilation(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit Circuit
	// We check if Compile works (valid constraints generation)
	_, errCompile := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(errCompile, "Circuit should compile")
}

// BenchmarkCompileTLE measures circuit compilation and constraint counting
func BenchmarkCompileTLE(b *testing.B) {
	var circuit Circuit

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
		if err != nil {
			b.Fatal(err)
		}

		if i == 0 {
			// Report constraints only once
			b.Logf("TLE Circuit Constraints: %d", ccs.GetNbConstraints())
		}
	}
}

// BenchmarkProveTLE measures full proving workflow (setup + prove)
// This is the critical feasibility test: MUST be < 10 minutes
func BenchmarkProveTLE(b *testing.B) {
	// Create mock witness
	witness := createMockWitness(b)

	// Compile circuit
	b.Log("Compiling TLE circuit...")
	startCompile := time.Now()
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		b.Fatal(err)
	}
	compileTime := time.Since(startCompile)
	b.Logf("Compilation time: %v", compileTime)
	b.Logf("Constraints: %d", ccs.GetNbConstraints())

	// Groth16 Setup (Trusted Setup Phase)
	b.Log("Running Groth16 setup...")
	startSetup := time.Now()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		b.Fatal(err)
	}
	setupTime := time.Since(startSetup)
	b.Logf("Setup time: %v", setupTime)

	// Proving (The critical benchmark)
	b.ResetTimer() // Reset timer to exclude setup time from benchmark

	for i := 0; i < b.N; i++ {
		startProve := time.Now()

		// Generate witness
		fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
		if err != nil {
			b.Fatal(err)
		}

		// Create proof
		proof, err := groth16.Prove(ccs, pk, fullWitness)
		if err != nil {
			b.Fatal(err)
		}

		proveTime := time.Since(startProve)

		if i == 0 {
			b.Logf("Proving time: %v", proveTime)

			// Feasibility check
			tenMinutes := 10 * time.Minute
			if proveTime > tenMinutes {
				b.Errorf("FEASIBILITY FAIL: Proving time %v exceeds 10 minute threshold", proveTime)
				b.Log("RECOMMENDATION: Pivot to Track B (ZKVM)")
			} else {
				b.Logf("FEASIBILITY PASS: Proving time %v is under 10 minute threshold", proveTime)
			}

			// Verify the proof works
			publicWitness, _ := fullWitness.Public()
			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				b.Fatal("Proof verification failed:", err)
			}
			b.Log("Proof verified successfully")
		}
	}
}

// createMockWitness generates a valid witness for benchmarking
func createMockWitness(tb testing.TB) Circuit {
	// Mock values (simplified for benchmark - real values would come from actual encryption)
	r2 := big.NewInt(123456789)

	// Mock sigma (32 random bytes)
	sigma := [32]uints.U8{}
	for i := 0; i < 32; i++ {
		sigma[i] = uints.NewU8(uint8(i))
	}

	// Mock V, W (would be computed from actual encryption)
	v := [32]uints.U8{}
	w := [32]uints.U8{}
	for i := 0; i < 32; i++ {
		v[i] = uints.NewU8(uint8(i + 32))
		w[i] = uints.NewU8(uint8(i + 64))
	}

	// Mock public inputs (these would come from actual IBE encryption)
	// Qid (G2 point on BLS12-381)
	qidX0 := big.NewInt(1)
	qidX1 := big.NewInt(2)
	qidY0 := big.NewInt(3)
	qidY1 := big.NewInt(4)

	// PK (G1 point)
	pkX := big.NewInt(5)
	pkY := big.NewInt(6)

	// U (G1 point from r * G)
	uX := big.NewInt(7)
	uY := big.NewInt(8)

	// Commitment C
	c := big.NewInt(999)

	// Context hash (split into hi/lo)
	ctxHi := big.NewInt(100)
	ctxLo := big.NewInt(200)

	// H3 counter (for rejection sampling)
	h3Count := big.NewInt(0)

	return Circuit{
		QidX0:   qidX0,
		QidX1:   qidX1,
		QidY0:   qidY0,
		QidY1:   qidY1,
		PKX:     pkX,
		PKY:     pkY,
		UX:      uX,
		UY:      uY,
		V:       v,
		W:       w,
		C:       c,
		CtxHi:   ctxHi,
		CtxLo:   ctxLo,
		R2:      r2,
		Sigma:   sigma,
		H3Count: h3Count,
	}
}

// TestProveVerifyFlow tests the complete prove-verify cycle with mock data
func TestProveVerifyFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping full prove-verify test in short mode")
	}

	witness := createMockWitness(t)

	// Compile
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		t.Fatal(err)
	}

	// Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal(err)
	}

	// Prove
	fullWitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}

	proof, err := groth16.Prove(ccs, pk, fullWitness)
	if err != nil {
		t.Fatal(err)
	}

	// Verify
	publicWitness, err := fullWitness.Public()
	if err != nil {
		t.Fatal(err)
	}

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatal("Verification failed:", err)
	}

	t.Log("Prove-Verify cycle completed successfully")
}
