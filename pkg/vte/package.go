package vte

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"vte-tlock/circuits/commitment"
)

// GenerateVTEParams contains all inputs needed to generate a VTEPackage.
type GenerateVTEParams struct {
	Round          uint64
	ChainHash      []byte
	FormatID       string
	R2             []byte // 32-byte secret scalar
	CtxHash        []byte // 32-byte context hash
	DrandEndpoints []string
	GenerateProof  bool // Whether to generate ZK proof (expensive, ~1.5s)
}

// GenerateVTE creates a VTEPackage from the provided parameters.
// This uses REAL tlock encryption and optionally generates ZK proofs.
func GenerateVTE(params *GenerateVTEParams) (*VTEPackage, error) {
	if len(params.R2) != 32 {
		return nil, fmt.Errorf("R2 secret must be 32 bytes")
	}
	if len(params.CtxHash) != 32 {
		return nil, fmt.Errorf("CtxHash must be 32 bytes")
	}

	pkg := &VTEPackage{
		Round: params.Round,
		NetworkID: NetworkID{
			ChainHash:          params.ChainHash,
			TlockVersion:       "v1.0.0",
			CiphertextFormatID: params.FormatID,
			TrustChainHash:     false,
			DrandEndpoints:     params.DrandEndpoints,
		},
		CtxHash: params.CtxHash,
	}

	// 1. REAL ENCRYPTION: Call tlock.Encrypt with r2 as payload
	ctx := context.Background()
	capsule, err := Encrypt(ctx, params.ChainHash, params.Round, params.R2, params.DrandEndpoints)
	if err != nil {
		return nil, fmt.Errorf("tlock encryption failed: %w", err)
	}
	pkg.Capsule = capsule

	// 2. Parse Capsule to get REAL CipherFields
	fields, err := ParseCapsule(pkg.Capsule, params.FormatID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse encrypted capsule: %w", err)
	}
	pkg.CipherFields = fields

	// 3. REAL SECP256K1 POINT: R2 = r2 * G
	compressed, r2Pub, err := ComputeR2Point(params.R2)
	if err != nil {
		return nil, fmt.Errorf("failed to compute R2 point: %w", err)
	}
	pkg.R2Compressed = compressed
	pkg.R2Pub = r2Pub

	// 4. REAL COMMITMENT: C = MiMC(DST, r2, ctx_hash)
	// Using MiMC for ZK circuit compatibility
	commitmentBytes, err := commitment.ComputeCommitmentHash(params.R2, params.CtxHash)
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment: %w", err)
	}
	pkg.C = commitmentBytes

	// 5. Generate ZK Proof (optional but recommended for verifiability)
	if params.GenerateProof {
		proofResult, err := commitment.Prove(nil, &commitment.WitnessInput{
			R2:      params.R2,
			CtxHash: params.CtxHash,
			C:       commitmentBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("ZK proof generation failed: %w", err)
		}
		pkg.ProofSECP = proofResult.Proof
	} else {
		pkg.ProofSECP = []byte{} // Empty if not generating
	}

	// 6. TLE proof is empty (full IBE proof not implemented yet)
	pkg.ProofTLE = []byte{}

	return pkg, nil
}

// splitBytes splits 32 bytes into 2x16 byte limbs (as expected by R2PublicInputs)
func splitBytes(b []byte) [2][16]byte {
	var res [2][16]byte
	if len(b) == 32 {
		copy(res[0][:], b[:16])
		copy(res[1][:], b[16:])
	}
	return res
}

// Helper for UI to generate Context Hash from sessionID and refundTx
func ComputeCtxHash(sessionID string, refundTxHex string) ([]byte, error) {
	refundTx, err := hex.DecodeString(refundTxHex)
	if err != nil {
		return nil, fmt.Errorf("invalid refund tx hex: %w", err)
	}

	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write(refundTx)
	return h.Sum(nil), nil
}
