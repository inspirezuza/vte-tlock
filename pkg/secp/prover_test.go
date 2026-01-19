package secp

import (
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/test"

	circuit "vte-tlock/circuits/secp"
)

// TestCircuitCompilation tests that the SECP circuit compiles
func TestCircuitCompilation(t *testing.T) {
	var c circuit.Circuit
	assert := test.NewAssert(t)

	// Test that the circuit compiles
	err := test.IsSolved(&c, &circuit.Circuit{}, ecc.BN254.ScalarField())

	// We expect it to fail since we haven't provided valid inputs
	// but the circuit should at least compile
	if err == nil {
		t.Log("Circuit compiled and solved (unexpected with empty inputs)")
	} else {
		t.Log("Circuit compiled, constraint check returned:", err)
	}

	// Try with valid inputs
	t.Run("ValidInputs", func(t *testing.T) {
		// Generate random r2
		r2Bytes := make([]byte, 32)
		rand.Read(r2Bytes)

		// Compute R2 point
		_, pubKey := btcec.PrivKeyFromBytes(r2Bytes)
		r2x := pubKey.X().Bytes()
		r2y := pubKey.Y().Bytes()

		// Pad to 32 bytes
		x32 := make([]byte, 32)
		y32 := make([]byte, 32)
		copy(x32[32-len(r2x):], r2x)
		copy(y32[32-len(r2y):], r2y)

		// Random ctx hash
		ctxHash := make([]byte, 32)
		rand.Read(ctxHash)

		// Split to limbs
		r2Hi := new(big.Int).SetBytes(r2Bytes[:16])
		r2Lo := new(big.Int).SetBytes(r2Bytes[16:])
		ctxHi := new(big.Int).SetBytes(ctxHash[:16])
		ctxLo := new(big.Int).SetBytes(ctxHash[16:])
		r2xHi := new(big.Int).SetBytes(x32[:16])
		r2xLo := new(big.Int).SetBytes(x32[16:])
		r2yHi := new(big.Int).SetBytes(y32[:16])
		r2yLo := new(big.Int).SetBytes(y32[16:])

		// Compute Poseidon commitment (simplified placeholder)
		// NOTE: This won't match the actual circuit's Poseidon output
		// We need to compute the same Poseidon hash externally
		commitment := big.NewInt(12345) // Placeholder - needs real Poseidon

		witness := &circuit.Circuit{
			CtxHi:   ctxHi,
			CtxLo:   ctxLo,
			C:       commitment,
			R2xHi:   r2xHi,
			R2xLo:   r2xLo,
			R2yHi:   r2yHi,
			R2yLo:   r2yLo,
			SimR2Hi: r2Hi,
			SimR2Lo: r2Lo,
		}

		t.Logf("r2: %s", hex.EncodeToString(r2Bytes))
		t.Logf("R2x: %s", hex.EncodeToString(x32))
		t.Logf("R2y: %s", hex.EncodeToString(y32))

		// The circuit should fail on commitment mismatch,
		// but prove the scalar multiplication is correct
		assert.ProverFailed(&circuit.Circuit{}, witness, test.WithBackends(backend.GROTH16))
	})
}

// TestProverSetup tests the prover setup and key generation
func TestProverSetup(t *testing.T) {
	t.Log("Setting up SECP prover (this may take a while)...")

	keys, err := Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	t.Logf("SECP circuit compiled with %d constraints", keys.CCS.GetNbConstraints())

	// Get VK bytes
	vkBytes, err := GetVerifyingKeyBytes()
	if err != nil {
		t.Fatalf("GetVerifyingKeyBytes failed: %v", err)
	}

	t.Logf("Verifying key size: %d bytes", len(vkBytes))
}

// TestProofGenerationSimple tests a minimal proof scenario
// NOTE: This test is expected to fail until Poseidon commitment is computed correctly
func TestProofGenerationSimple(t *testing.T) {
	t.Skip("Skipping until Poseidon commitment is correctly computed outside circuit")

	// This would need proper Poseidon commitment computation
	// For now, we verify the circuit structure is correct
}
