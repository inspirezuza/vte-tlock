package vte

import (
	"errors"
)

// VTEPackageV2 represents the v0.2 schema
type VTEPackageV2 struct {
	Version string      `json:"version"` // "vte-tlock/0.2"
	Tlock   TlockInfo   `json:"tlock"`
	Context ContextInfo `json:"context"`
	Public  PublicInfo  `json:"public"`
	Proofs  ProofsInfo  `json:"proofs"`
	Meta    MetaInfo    `json:"meta,omitempty"`
}

type TlockInfo struct {
	DrandChainHash     []byte `json:"drand_chain_hash"` // Hex or Base64
	Round              uint64 `json:"round"`
	CiphertextFormatID string `json:"ciphertext_format_id"` // "tlock_v1_age_pairing"
	Capsule            []byte `json:"capsule"`              // The actual ciphertext
	CapsuleHash        []byte `json:"capsule_hash"`         // SHA256(Capsule)
}

type ContextInfo struct {
	Schema      string   `json:"schema"` // "ctx_v2"
	Fields      []string `json:"fields"` // ["drand_chain_hash", "round", "capsule_hash", "session_id", "refund_tx_hex"]
	SessionID   string   `json:"session_id,omitempty"`
	RefundTxHex string   `json:"refund_tx_hex,omitempty"`
	CtxHash     []byte   `json:"ctx_hash"` // The binding hash
}

type PublicInfo struct {
	R2         R2Info `json:"r2"`
	Commitment []byte `json:"commitment"` // MiMC(R2, CtxHash)
}

type R2Info struct {
	Format string `json:"format"` // "sec1_compressed_hex"
	Value  []byte `json:"value"`  // 33-byte compressed point
}

type ProofsInfo struct {
	Commitment  CommitmentProofInfo `json:"commitment"`
	SecpSchnorr SecpSchnorrInfo     `json:"secp_schnorr"`
	TLE         TLEProofInfo        `json:"tle"`
}

type CommitmentProofInfo struct {
	System       string                 `json:"system"`     // "groth16_bn254"
	CircuitID    string                 `json:"circuit_id"` // Verification Key Hash
	VkHash       string                 `json:"vk_hash"`    // redundant but explicit
	PublicInputs CommitmentPublicInputs `json:"public_inputs"`
	ProofB64     []byte                 `json:"proof_b64"`
}

type CommitmentPublicInputs struct {
	CtxHash    []byte `json:"ctx_hash"`
	Commitment []byte `json:"commitment"`
}

type SecpSchnorrInfo struct {
	Scheme       string   `json:"scheme"`      // "schnorr_fs_v1"
	BindFields   []string `json:"bind_fields"` // ["R2", "commitment", "ctx_hash", "capsule_hash"]
	SignatureB64 []byte   `json:"signature_b64"`
}

type TLEProofInfo struct {
	Status   string `json:"status"` // "not_implemented" | "implemented"
	ProofB64 []byte `json:"proof_b64,omitempty"`
}

type MetaInfo struct {
	UnlockTimeUTC string `json:"unlock_time_utc,omitempty"`
}

// Validation errors
var (
	ErrVersionMismatch = errors.New("version mismatch")
	ErrNetworkMismatch = errors.New("network/chain ID mismatch")
	ErrRoundMismatch   = errors.New("round mismatch")
	ErrCtxHashMismatch = errors.New("context hash mismatch")
)
