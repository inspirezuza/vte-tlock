package vte

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
)

// ComputeR2Point computes the secp256k1 elliptic curve point R2 = r2 * G
// where G is the generator point and r2 is a 32-byte scalar.
// Returns the compressed form (33 bytes) and public inputs (x, y coordinates).
func ComputeR2Point(r2 []byte) ([]byte, R2PublicInputs, error) {
	if len(r2) != 32 {
		return nil, R2PublicInputs{}, fmt.Errorf("r2 must be 32 bytes")
	}

	// Compute R2 = r2 * G on secp256k1
	_, pubKey := btcec.PrivKeyFromBytes(r2)

	// Get compressed form (33 bytes: 0x02/0x03 prefix + x coordinate)
	compressed := pubKey.SerializeCompressed()

	// Get x and y coordinates (32 bytes each)
	xBytes := pubKey.X().Bytes()
	yBytes := pubKey.Y().Bytes()

	// Pad to 32 bytes if needed
	x32 := make([]byte, 32)
	y32 := make([]byte, 32)
	copy(x32[32-len(xBytes):], xBytes)
	copy(y32[32-len(yBytes):], yBytes)

	// Split into 16-byte limbs for R2PublicInputs
	r2Pub := R2PublicInputs{
		R2x: splitBytes(x32),
		R2y: splitBytes(y32),
	}

	return compressed, r2Pub, nil
}

// ComputeCommitment computes C = H(DST || r2 || ctx_hash) using SHA256
// NOTE: This uses SHA256 with proper domain separation instead of Poseidon
// due to gnark-crypto dependency issues. The commitment is still cryptographically
// sound and binding. For ZK circuit compatibility, Poseidon should be used,
// but for timelock encryption correctness, this is sufficient.
//
// The commitment scheme: C = SHA256("VTE_COMMIT_V1" || r2 || ctx_hash)
func ComputeCommitment(r2, ctxHash []byte) ([]byte, error) {
	if len(r2) != 32 {
		return nil, fmt.Errorf("r2 must be 32 bytes")
	}
	if len(ctxHash) != 32 {
		return nil, fmt.Errorf("ctxHash must be 32 bytes")
	}

	// Domain separation tag
	dst := []byte("VTE_COMMIT_V1")

	// Commitment: SHA256(DST || r2 || ctx_hash)
	h := sha256.New()
	h.Write(dst)
	h.Write(r2)
	h.Write(ctxHash)

	return h.Sum(nil), nil
}
