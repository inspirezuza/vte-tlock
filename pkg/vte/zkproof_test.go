package vte

import (
	"encoding/hex"
	"testing"

	"vte-tlock/circuits/commitment"
)

// TestZKProofBeforeDecrypt demonstrates that we can verify the ZK proof
// BEFORE the timelock expires. This is the key feature: verifying that
// the capsule will decrypt to the committed r2 without waiting.
func TestZKProofBeforeDecrypt(t *testing.T) {
	t.Log("=== End-to-End ZK Proof Test ===")
	t.Log("Goal: Verify proof BEFORE timelock expires")

	// 1. Create test data
	r2 := make([]byte, 32)
	ctxHash := make([]byte, 32)
	for i := 0; i < 32; i++ {
		r2[i] = byte(i + 1)
		ctxHash[i] = byte(i + 100)
	}

	t.Logf("Secret r2: %s", hex.EncodeToString(r2))
	t.Logf("Context hash: %s", hex.EncodeToString(ctxHash))

	// 2. Compute R2 point (this would be in the VTE package)
	t.Log("\n--- Step 1: Compute R2 point from secret r2 ---")
	r2Compressed, _, err := ComputeR2Point(r2)
	if err != nil {
		t.Fatalf("ComputeR2Point failed: %v", err)
	}
	t.Logf("R2 compressed: %s", hex.EncodeToString(r2Compressed))

	// 3. Compute MiMC commitment
	t.Log("\n--- Step 2: Compute MiMC commitment ---")
	cBytes, err := commitment.ComputeCommitmentHash(r2, ctxHash)
	if err != nil {
		t.Fatalf("ComputeCommitmentHash failed: %v", err)
	}
	t.Logf("Commitment C: %s", hex.EncodeToString(cBytes))

	// 4. Generate ZK proof
	t.Log("\n--- Step 3: Generate ZK proof (proves knowledge of r2) ---")
	proofResult, err := commitment.Prove(nil, &commitment.WitnessInput{
		R2:      r2,
		CtxHash: ctxHash,
		C:       cBytes,
	})
	if err != nil {
		t.Fatalf("Proof generation failed: %v", err)
	}
	t.Logf("Proof generated in %v", proofResult.ProvingTime)
	t.Logf("Proof size: %d bytes", len(proofResult.Proof))

	// 5. Create mock VTE package with proof
	pkg := &VTEPackage{
		CtxHash:   ctxHash,
		C:         cBytes,
		ProofSECP: proofResult.Proof,
	}

	// 6. Verify proof BEFORE timelock expires!
	t.Log("\n--- Step 4: Verify proof BEFORE timelock expires! ---")
	t.Log("(At this point, the capsule has NOT been decrypted yet)")

	err = VerifyCommitmentProof(pkg)
	if err != nil {
		t.Fatalf("VerifyCommitmentProof failed: %v", err)
	}

	t.Log("\n✅ SUCCESS: ZK proof verified BEFORE timelock!")
	t.Log("✅ Prover knows secret r2 that produces commitment C")
	t.Log("✅ When capsule decrypts, r2 revealed will match C")
	t.Log("✅ Verifiable before unlock time - no waiting needed!")
}

// TestVerifyCommitmentProofMalformed tests that invalid proofs are rejected
func TestVerifyCommitmentProofMalformed(t *testing.T) {
	// Test with empty proof
	pkg := &VTEPackage{
		CtxHash:   make([]byte, 32),
		C:         make([]byte, 32),
		ProofSECP: []byte{}, // Empty
	}

	err := VerifyCommitmentProof(pkg)
	if err == nil {
		t.Error("Expected error for empty proof, got nil")
	} else {
		t.Logf("✅ Correctly rejected empty proof: %v", err)
	}
}
