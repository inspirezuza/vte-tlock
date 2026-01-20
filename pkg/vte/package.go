package vte

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"vte-tlock/circuits/commitment"
)

// GenerateVTEParams contains all inputs needed to generate a VTEPackage.
type GenerateVTEParams struct {
	Round     uint64
	ChainHash []byte
	FormatID  string
	SessionID string // Added for binding (e.g. UUID)
	R2        []byte // 32-byte secret scalar
	RefundTx  []byte // Transaction data for binding
	// ...
	CtxHash         []byte   // Optional: pre-computed context hash (not recommended)
	DrandEndpoints  []string // Endpoints to use for encryption (e.g. local proxy)
	StoredEndpoints []string // Endpoints to write to package (e.g. real URL). If empty, uses DrandEndpoints.
	GenerateProof   bool     // Whether to generate ZK proof (expensive, ~1.5s)

	// WASM-specific: pre-fetched chain info and beacon (avoids HTTP from WASM)
	ChainInfoJSON      string // JSON response from /{chainHash}/info (required in WASM)
	BeaconSignatureHex string // Signature hex from /{chainHash}/public/{round} (required in WASM)
}

// GenerateVTE creates a VTEPackage from the provided parameters.
// This uses REAL tlock encryption and optionally generates ZK proofs.
// GenerateVTE creates a VTEPackage from the provided parameters.
// This uses REAL tlock encryption and optionally generates ZK proofs.
func GenerateVTE(params *GenerateVTEParams) (*VTEPackageV2, error) {
	if len(params.R2) != 32 {
		return nil, fmt.Errorf("R2 secret must be 32 bytes")
	}

	// 1. REAL ENCRYPTION
	ctx := context.Background()
	var capsule []byte
	var err error

	// Use prefetched data if available (required for WASM builds)
	if params.ChainInfoJSON != "" {
		capsule, err = EncryptWithPrefetch(ctx, params.ChainHash, params.Round, params.R2, params.ChainInfoJSON, params.BeaconSignatureHex)
	} else {
		capsule, err = Encrypt(ctx, params.ChainHash, params.Round, params.R2, params.DrandEndpoints)
	}
	if err != nil {
		return nil, fmt.Errorf("tlock encryption failed: %w", err)
	}

	// Compute Capsule Hash (SHA256)
	capsuleHash := sha256.Sum256(capsule)

	// 2. COMPUTE BINDING CONTEXT HASH
	ctxParams := &CtxHashParams{
		SessionID:   params.SessionID,
		RefundTx:    params.RefundTx,
		ChainHash:   params.ChainHash,
		Round:       params.Round,
		CapsuleHash: capsuleHash[:],
	}

	ctxHash, err := ComputeFullCtxHash(ctxParams)
	if err != nil {
		return nil, fmt.Errorf("ctx_hash computation failed: %w", err)
	}

	// 3. Compute R2 Compressed Point (R2 = r2 * G)
	compressedR2, err := ComputeR2Point(params.R2)
	if err != nil {
		return nil, fmt.Errorf("failed to compute R2 point: %w", err)
	}

	// 4. Compute Commitment (MiMC of R2, CtxHash)
	commitmentBytes, err := commitment.ComputeCommitmentHash(params.R2, ctxHash)
	if err != nil {
		return nil, fmt.Errorf("failed to compute commitment: %w", err)
	}

	// 5. Generate ZK Proof (Groth16)
	var commitmentProof CommitmentProofInfo
	if params.GenerateProof {
		proofResult, err := commitment.Prove(nil, &commitment.WitnessInput{
			R2:      params.R2,
			CtxHash: ctxHash,
			C:       commitmentBytes,
		})
		if err != nil {
			return nil, fmt.Errorf("ZK proof generation failed: %w", err)
		}
		commitmentProof = CommitmentProofInfo{
			System:    "groth16_bn254",
			CircuitID: commitment.CircuitID,
			VkHash:    commitment.CircuitID, // Using CircuitID as VK hash for now
			PublicInputs: CommitmentPublicInputs{
				CtxHash:    ctxHash,
				Commitment: commitmentBytes,
			},
			ProofB64: proofResult.Proof,
		}
	}

	// 6. Generate Schnorr Proof (R2 = r2*G binding to CtxHash)
	// Note: We bind to specific fields as per V2 spec to be explicit
	// Actually Schnorr signature signs the message.
	// We sign the CtxHash.
	proofSecp, err := GenerateSchnorrProof(params.R2, ctxHash)
	if err != nil {
		return nil, fmt.Errorf("schnorr proof generation failed: %w", err)
	}

	// Construct V2 Package
	pkg := &VTEPackageV2{
		Version: "vte-tlock/0.2",
		Tlock: TlockInfo{
			DrandChainHash:     params.ChainHash,
			Round:              params.Round,
			CiphertextFormatID: params.FormatID,
			Capsule:            capsule,
			CapsuleHash:        capsuleHash[:],
		},
		Context: ContextInfo{
			Schema:      "ctx_v2",
			Fields:      []string{"drand_chain_hash", "round", "capsule_hash", "session_id", "refund_tx_hex"},
			SessionID:   params.SessionID,
			RefundTxHex: hex.EncodeToString(params.RefundTx),
			CtxHash:     ctxHash,
		},
		Public: PublicInfo{
			R2: R2Info{
				Format: "sec1_compressed_hex",
				Value:  compressedR2,
			},
			Commitment: commitmentBytes,
		},
		Proofs: ProofsInfo{
			Commitment: commitmentProof,
			SecpSchnorr: SecpSchnorrInfo{
				Scheme:       "schnorr_fs_v1",
				BindFields:   []string{"R2", "commitment", "ctx_hash", "capsule_hash"}, // Implicitly via CtxHash
				SignatureB64: proofSecp.Signature,
			},
			TLE: TLEProofInfo{
				Status: "not_implemented",
			},
		},
		Meta: MetaInfo{
			UnlockTimeUTC: "", // Informational, filled by UI if needed
		},
	}

	return pkg, nil
}

// CtxHashParams contains all parameters for full context hash computation
type CtxHashParams struct {
	SessionID   string
	RefundTx    []byte
	ChainHash   []byte
	Round       uint64
	CapsuleHash []byte // SHA256(capsule) required for V2
}

// ComputeFullCtxHash computes context hash according to V2 spec.
// Order: ChainHash || Round || CapsuleHash || SessionID || RefundTx
func ComputeFullCtxHash(params *CtxHashParams) ([]byte, error) {
	if params == nil {
		return nil, fmt.Errorf("params cannot be nil")
	}

	h := sha256.New()
	// Domain separator
	h.Write([]byte("VTE_CTX_V2"))

	// 1. Chain Hash
	if len(params.ChainHash) != 32 {
		return nil, fmt.Errorf("chain_hash must be 32 bytes")
	}
	h.Write(params.ChainHash)

	// 2. Round (8 bytes BE)
	roundBytes := make([]byte, 8)
	roundBytes[0] = byte(params.Round >> 56)
	roundBytes[1] = byte(params.Round >> 48)
	roundBytes[2] = byte(params.Round >> 40)
	roundBytes[3] = byte(params.Round >> 32)
	roundBytes[4] = byte(params.Round >> 24)
	roundBytes[5] = byte(params.Round >> 16)
	roundBytes[6] = byte(params.Round >> 8)
	roundBytes[7] = byte(params.Round)
	h.Write(roundBytes)

	// 3. Capsule Hash
	if len(params.CapsuleHash) != 32 {
		return nil, fmt.Errorf("capsule_hash must be 32 bytes SHA256")
	}
	h.Write(params.CapsuleHash)

	// 4. Session ID
	h.Write([]byte(params.SessionID))

	// 5. Refund Tx
	h.Write(params.RefundTx)

	return h.Sum(nil), nil
}

// VerifyCtxHashBinding verifies V2 context hash binding
func VerifyCtxHashBinding(pkg *VTEPackageV2) error {
	refundTx, err := hex.DecodeString(pkg.Context.RefundTxHex)
	if err != nil {
		return fmt.Errorf("invalid refund tx hex: %w", err)
	}

	// Recompute the full context hash
	expectedCtxHash, err := ComputeFullCtxHash(&CtxHashParams{
		SessionID:   pkg.Context.SessionID,
		RefundTx:    refundTx,
		ChainHash:   pkg.Tlock.DrandChainHash,
		Round:       pkg.Tlock.Round,
		CapsuleHash: pkg.Tlock.CapsuleHash,
	})
	if err != nil {
		return fmt.Errorf("failed to compute expected ctx_hash: %w", err)
	}

	// Compare with package's ctx_hash
	if !bytes.Equal(expectedCtxHash, pkg.Context.CtxHash) {
		return fmt.Errorf("ctx_hash binding failed: calculated %x, but package claims %x", expectedCtxHash, pkg.Context.CtxHash)
	}

	// Also verify Capsule Hash matches actual Capsule
	actualCapsuleHash := sha256.Sum256(pkg.Tlock.Capsule)
	if !bytes.Equal(actualCapsuleHash[:], pkg.Tlock.CapsuleHash) {
		return fmt.Errorf("capsule integrity check failed: SHA256(capsule) != capsule_hash")
	}

	return nil
}
