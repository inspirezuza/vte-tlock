package vte

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// NetworkID defines the strict network parameters for verification.
type NetworkID struct {
	ChainHash          []byte
	TlockVersion       string // e.g., "v1.0.0"
	CiphertextFormatID string // e.g., "tlock_v1_age_pairing"
	TrustChainHash     bool   // MUST be false for this version
	DrandEndpoints     []string
}

// VTEPackage is the transferrable verification package.
type VTEPackage struct {
	Round           uint64
	NetworkID       NetworkID
	Capsule         []byte
	CapsuleChecksum []byte // BLAKE3(Capsule)
	CipherFields    CipherFields // Parsed fields bindable to proof
	CtxHash         [32]byte
	C               [32]byte // Commitment Poseidon(DST, r2, ctx)
	R2Compressed    [33]byte // Compressed secp256k1 point
	R2Pub           R2PublicInputs
	ProofSECP       []byte
	ProofTLE        []byte
}

// R2PublicInputs holds the limbs for the SECP proof.
type R2PublicInputs struct {
	R2x [2][16]byte // 2 limbs of 16 bytes (uint128)
	R2y [2][16]byte
}

// CipherFields represents the parsed components of the ciphertext.
// This structure depends on CiphertextFormatID.
type CipherFields struct {
	// For "tlock_v1_age_pairing"
	EphemeralPubKey []byte // Compressed or uncompressed point
	Mask            []byte
	Tag             []byte
	Ciphertext      []byte
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
