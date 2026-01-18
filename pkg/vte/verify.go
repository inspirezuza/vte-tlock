package vte

import (
	"bytes"
	"fmt"
)

// VerifyVTE performs the strict verification of the VTE package (Section 8 of Spec).
// It does NOT run the ZK proofs yet (that's a separate step usually, but we can orchestrate it here).
// For v0.2.1, this function orchestrates the structural and binding checks.
func VerifyVTE(
	pkg *VTEPackage,
	expectedRound uint64,
	expectedChainHash []byte,
	expectedFormatID string,
	expectedCtxHash [32]byte,
) error {
	// 1. Check NetworkID (Strict binding)
	if err := pkg.NetworkID.Validate(expectedChainHash, expectedFormatID); err != nil {
		return err
	}

	// 2. Check Round
	if err := pkg.ValidateHeader(expectedRound); err != nil {
		return err
	}

	// 3. Check Context Hash
	if len(pkg.CtxHash) != 32 {
		return fmt.Errorf("invalid ctx_hash length: %d", len(pkg.CtxHash))
	}
	if !bytes.Equal(pkg.CtxHash, expectedCtxHash[:]) {
		return fmt.Errorf("ctx hash mismatch: have %x, want %x", pkg.CtxHash, expectedCtxHash)
	}

	// Structural Validation
	if len(pkg.C) != 32 {
		return fmt.Errorf("invalid C length: %d", len(pkg.C))
	}
	if len(pkg.R2Compressed) != 33 {
		return fmt.Errorf("invalid R2Compressed length: %d", len(pkg.R2Compressed))
	}

	// 4. Parse Capsule and Verify Integrity
	fields, err := ParseCapsule(pkg.Capsule, pkg.NetworkID.CiphertextFormatID)
	if err != nil {
		return fmt.Errorf("failed to parse capsule: %w", err)
	}

	// Assert fields match what's in the package (Binding check)
	// This ensures the Prover didn't lie about the fields fed to the proof.
	if !equalCipherFields(fields, pkg.CipherFields) {
		return fmt.Errorf("cipher fields in package do not match parsed capsule")
	}

	// 5. Verify Proof_TLE (Placeholder)
	// TODO: Call backend verifier
	// verifyProofTLE(pkg.ProofTLE, ... public inputs ...)

	// 6. Decompress R2 and Verify Proof_SECP (Placeholder)
	// TODO: Decompress pkg.R2Compressed, check on-curve
	// TODO: Call backend verifier
	// verifyProofSECP(pkg.ProofSECP, ... public inputs ...)

	return nil
}

func equalCipherFields(a, b CipherFields) bool {
	return bytes.Equal(a.EphemeralPubKey, b.EphemeralPubKey) &&
		bytes.Equal(a.Mask, b.Mask) &&
		bytes.Equal(a.Tag, b.Tag) &&
		bytes.Equal(a.Ciphertext, b.Ciphertext)
}
