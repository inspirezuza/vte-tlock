package vte

import (
	"bytes"
	"encoding/hex"
	"fmt"
)

// VerifyVTE performs the strict verification of the VTE package (Section 8 of Spec).
// It does NOT run the ZK proofs yet (that's a separate step usually, but we can orchestrate it here).
// For v0.2.1, this function orchestrates the structural and binding checks.
// VerifyVTE performs strict verification of the VTE package V2.
// It verifies:
// 1. Structure & Version
// 2. Cryptographic Bindings (CtxHash, CapsuleHash)
// 3. ZK Proofs (Commitment)
// 4. Schnorr Proofs (R2)
func VerifyVTE(
	pkg *VTEPackageV2,
	expectedRound uint64,
	expectedChainHash []byte, // Optional verification against external expectation
	expectedFormatID string,
	expectedSessionID string,
	expectedRefundTx []byte,
) error {
	// 1. Check Version
	if pkg.Version != "vte-tlock/0.2" {
		return fmt.Errorf("%w: have %s, want vte-tlock/0.2", ErrVersionMismatch, pkg.Version)
	}

	// 2. Check Chain Binding (if provided)
	if len(expectedChainHash) > 0 && !bytes.Equal(pkg.Tlock.DrandChainHash, expectedChainHash) {
		return fmt.Errorf("%w: have %x, want %x", ErrNetworkMismatch, pkg.Tlock.DrandChainHash, expectedChainHash)
	}

	// 3. Check Round Binding (if provided)
	if expectedRound > 0 && pkg.Tlock.Round != expectedRound {
		return fmt.Errorf("%w: have %d, want %d", ErrRoundMismatch, pkg.Tlock.Round, expectedRound)
	}

	// 4. Check Context Hash Binding (CRITICAL)
	// This proves that the CtxHash actually binds the Capsule, Round, Chain, etc.
	if err := VerifyCtxHashBinding(pkg); err != nil {
		return fmt.Errorf("ctx_hash binding validation failed: %w", err)
	}

	// 5. Verify against expected Session/Refund if provided (Policy check)
	if expectedSessionID != "" && pkg.Context.SessionID != expectedSessionID {
		return fmt.Errorf("session ID mismatch: have %s, want %s", pkg.Context.SessionID, expectedSessionID)
	}
	if len(expectedRefundTx) > 0 {
		haveRefundTx, _ := hex.DecodeString(pkg.Context.RefundTxHex)
		if !bytes.Equal(haveRefundTx, expectedRefundTx) {
			return fmt.Errorf("refund tx mismatch")
		}
	}

	// 6. Verify ZK Commitment Proof (SECP)
	// Checks that prover knew r2 such that Commitment = MiMC(r2, CtxHash)
	if len(pkg.Proofs.Commitment.ProofB64) > 0 {
		if err := VerifyCommitmentProof(pkg); err != nil {
			return fmt.Errorf("ZK proof verification failed: %w", err)
		}
	} else {
		return fmt.Errorf("missing commitment proof")
	}

	// 7. Verify Schnorr Proof (R2 = r2*G)
	// Checks that Prover knows discrete log of R2
	if pkg.Proofs.SecpSchnorr.SignatureB64 != nil {
		// Verify signature against CtxHash
		if err := VerifySchnorrProof(pkg.Public.R2.Value, pkg.Context.CtxHash, &ProofSecp{
			Signature: pkg.Proofs.SecpSchnorr.SignatureB64,
		}); err != nil {
			return fmt.Errorf("schnorr proof verification failed: %w", err)
		}
	} else {
		return fmt.Errorf("missing schnorr proof")
	}

	return nil
}
