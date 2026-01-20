package commitment

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// embeddedVKCache caches the deserialized embedded VK
var (
	embeddedVKCache groth16.VerifyingKey
	embeddedVKOnce  sync.Once
	embeddedVKErr   error
)

// getEmbeddedVK returns the deserialized embedded VK (cached)
func getEmbeddedVK() (groth16.VerifyingKey, error) {
	embeddedVKOnce.Do(func() {
		if len(EmbeddedVK) == 0 {
			embeddedVKErr = fmt.Errorf("embedded VK is empty - run 'go generate' first")
			return
		}

		embeddedVKCache = groth16.NewVerifyingKey(ecc.BN254)
		_, embeddedVKErr = embeddedVKCache.ReadFrom(bytes.NewReader(EmbeddedVK))
		if embeddedVKErr != nil {
			embeddedVKErr = fmt.Errorf("failed to deserialize embedded VK: %w", embeddedVKErr)
		}
	})
	return embeddedVKCache, embeddedVKErr
}

// VerifyWithEmbeddedVK verifies a commitment proof using ONLY the embedded VK
// This is the TRUSTLESS verification function - it NEVER uses prover-supplied VK
//
// Parameters:
//   - proofBytes: The serialized Groth16 proof
//   - C: The commitment value (32 bytes)
//   - ctxHash: The context hash (32 bytes)
//
// Returns:
//   - nil if proof is valid
//   - error if verification fails
//
// SECURITY: This function is trustless because:
//   - VK is embedded at compile time
//   - Prover cannot supply a fake VK
//   - CircuitID can be checked by verifier
func VerifyWithEmbeddedVK(proofBytes, C, ctxHash []byte) error {
	// 1. Get embedded VK (never from package/prover)
	vk, err := getEmbeddedVK()
	if err != nil {
		return fmt.Errorf("failed to load embedded VK: %w", err)
	}

	// 2. Build public witness from provided public inputs
	cBigInt := new(big.Int).SetBytes(C)
	ctxBigInt := new(big.Int).SetBytes(ctxHash)

	publicWitness := &Circuit{
		CtxHash: ctxBigInt,
		C:       cBigInt,
	}

	pubWitness, err := frontend.NewWitness(publicWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness creation failed: %w", err)
	}

	// 3. Deserialize proof
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return fmt.Errorf("proof deserialization failed: %w", err)
	}

	// 4. Verify using EMBEDDED VK only
	if err := groth16.Verify(proof, vk, pubWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// GetEmbeddedCircuitID returns the circuit ID (VK hash) for package validation
func GetEmbeddedCircuitID() string {
	return CircuitID
}

// GetEmbeddedVKHash returns the full VK hash
func GetEmbeddedVKHash() string {
	return FullVKHash
}

// ValidateCircuitID checks if the given circuit ID matches the embedded VK
func ValidateCircuitID(circuitID string) error {
	if circuitID != CircuitID {
		return fmt.Errorf("circuit ID mismatch: got %s, expected %s", circuitID, CircuitID)
	}
	return nil
}

// ComputeVKHash computes the SHA256 hash of raw VK bytes
// Can be used by verifiers to confirm VK authenticity
func ComputeVKHash(vkBytes []byte) string {
	hash := sha256.Sum256(vkBytes)
	return hex.EncodeToString(hash[:])
}
