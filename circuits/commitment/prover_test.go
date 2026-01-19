package commitment

import (
	"encoding/hex"
	"testing"
)

// TestCircuitSetup tests that the commitment circuit compiles and setup works
func TestCircuitSetup(t *testing.T) {
	t.Log("Setting up commitment prover...")

	keys, err := Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	t.Logf("Commitment circuit compiled with %d constraints", keys.CCS.GetNbConstraints())
	t.Log("✅ Setup successful!")
}

// TestFullProofFlow tests end-to-end proof generation and verification
func TestFullProofFlow(t *testing.T) {
	t.Log("Running full proof flow test...")

	// Setup
	keys, err := Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	t.Logf("Circuit has %d constraints", keys.CCS.GetNbConstraints())

	// Create test inputs (32 bytes each)
	r2 := make([]byte, 32)
	ctxHash := make([]byte, 32)

	// Fill with deterministic test data
	for i := 0; i < 32; i++ {
		r2[i] = byte(i + 1)
		ctxHash[i] = byte(i + 100)
	}

	// Compute commitment using native MiMC (matching circuit)
	cBytes, err := ComputeCommitmentHash(r2, ctxHash)
	if err != nil {
		t.Fatalf("ComputeCommitmentHash failed: %v", err)
	}

	t.Logf("r2: %s", hex.EncodeToString(r2))
	t.Logf("ctxHash: %s", hex.EncodeToString(ctxHash))
	t.Logf("Commitment C: %s", hex.EncodeToString(cBytes))

	// Create witness input
	input := &WitnessInput{
		R2:      r2,
		CtxHash: ctxHash,
		C:       cBytes,
	}

	// Generate proof
	t.Log("Generating proof...")
	result, err := Prove(keys, input)
	if err != nil {
		t.Fatalf("Prove failed: %v", err)
	}

	t.Logf("Proof generated in %v", result.ProvingTime)
	t.Logf("Proof size: %d bytes", len(result.Proof))

	// Verify proof
	t.Log("Verifying proof...")
	err = Verify(keys, result.Proof, input)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	t.Log("✅ Proof verified successfully!")
}

// TestInvalidWitness tests that invalid witness fails verification
func TestInvalidWitness(t *testing.T) {
	keys, err := Setup()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Create valid inputs
	r2 := make([]byte, 32)
	ctxHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		r2[i] = byte(i + 1)
		ctxHash[i] = byte(i + 100)
	}

	cBytes, _ := ComputeCommitmentHash(r2, ctxHash)

	// Try to prove with wrong r2
	wrongR2 := make([]byte, 32)
	copy(wrongR2, r2)
	wrongR2[0] = 0xFF // Modify first byte

	input := &WitnessInput{
		R2:      wrongR2,
		CtxHash: ctxHash,
		C:       cBytes,
	}

	// Proof generation should fail (or proof should not verify)
	result, err := Prove(keys, input)
	if err == nil && result.Success {
		// Proof generated, but it should fail verification
		err = Verify(keys, result.Proof, input)
		if err == nil {
			t.Error("Expected verification to fail with wrong r2, but it passed")
		} else {
			t.Log("✅ Correctly rejected invalid proof")
		}
	} else {
		t.Logf("✅ Proof generation correctly failed: %v", err)
	}
}

// TestVKSerialization tests verifying key serialization
func TestVKSerialization(t *testing.T) {
	vkBytes, err := GetVerifyingKeyBytes()
	if err != nil {
		t.Fatalf("GetVerifyingKeyBytes failed: %v", err)
	}

	t.Logf("Verifying key size: %d bytes", len(vkBytes))

	// Should be reasonably small for embedding
	if len(vkBytes) > 10000 {
		t.Logf("Warning: VK is larger than expected: %d bytes", len(vkBytes))
	}
}
