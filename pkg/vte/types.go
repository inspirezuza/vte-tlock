package vte

import (
	"bytes"
	"errors"
	"fmt"
)

// NetworkID defines the strict network parameters for verification.
type NetworkID struct {
	ChainHash          []byte   `json:"chain_hash"`
	TlockVersion       string   `json:"tlock_version"`
	CiphertextFormatID string   `json:"ciphertext_format_id"`
	TrustChainHash     bool     `json:"trust_chain_hash"`
	DrandEndpoints     []string `json:"drand_endpoints"`
}

// VTEPackage is the transferrable verification package.
type VTEPackage struct {
	Round           uint64         `json:"round"`
	NetworkID       NetworkID      `json:"network_id"`
	Capsule         []byte         `json:"capsule"`
	CapsuleChecksum []byte         `json:"capsule_checksum"` // BLAKE3(Capsule)
	CipherFields    CipherFields   `json:"cipher_fields"`    // Parsed fields bindable to proof
	CtxHash         []byte         `json:"ctx_hash"`         // [32]byte, JSON Base64
	C               []byte         `json:"c"`                // [32]byte, JSON Base64
	R2Compressed    []byte         `json:"r2_compressed"`    // [33]byte, JSON Base64
	R2Pub           R2PublicInputs `json:"r2_pub"`
	ProofSECP       []byte         `json:"proof_secp"`
	ProofTLE        []byte         `json:"proof_tle"`
}

// R2PublicInputs holds the limbs for the SECP proof.
type R2PublicInputs struct {
	R2x [2][16]byte `json:"r2x"` // 2 limbs of 16 bytes (uint128)
	R2y [2][16]byte `json:"r2y"`
}

// CipherFields represents the parsed components of the ciphertext.
// This structure depends on CiphertextFormatID.
type CipherFields struct {
	// For "tlock_v1_age_pairing"
	EphemeralPubKey []byte `json:"ephemeral_pub_key"` // Compressed or uncompressed point
	Mask            []byte `json:"mask"`
	Tag             []byte `json:"tag"`
	Ciphertext      []byte `json:"ciphertext"`
}

// Validation errors
var (
	ErrNetworkMismatch = errors.New("network ID mismatch")
	ErrRoundMismatch   = errors.New("round mismatch")
	ErrFormatMismatch  = errors.New("ciphertext format ID mismatch")
	ErrTrustChainHash  = errors.New("TrustChainHash must be false in v0.2.1")
)

// Validate checks the VTEPackage against expected parameters (Network Verification Phase).
func (n NetworkID) Validate(expectedChainHash []byte, expectedFormatID string) error {
	if n.TrustChainHash {
		return ErrTrustChainHash
	}
	if !bytes.Equal(n.ChainHash, expectedChainHash) {
		return fmt.Errorf("%w: have %x, want %x", ErrNetworkMismatch, n.ChainHash, expectedChainHash)
	}
	if n.CiphertextFormatID != expectedFormatID {
		return fmt.Errorf("%w: have %s, want %s", ErrFormatMismatch, n.CiphertextFormatID, expectedFormatID)
	}
	return nil
}

func (p *VTEPackage) ValidateHeader(expectedRound uint64) error {
	if p.Round != expectedRound {
		return fmt.Errorf("%w: have %d, want %d", ErrRoundMismatch, p.Round, expectedRound)
	}
	return nil
}
