package tle

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"vte-tlock/circuits/lib/sw_bls12381"
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
			embeddedVKErr = fmt.Errorf("embedded VK is empty - run key generation first")
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

// VerifyWithEmbeddedVK verifies a TLE proof using ONLY the embedded VK.
// Inputs match the public inputs of the circuit.
func VerifyWithEmbeddedVK(
	proofBytes []byte,
	qid *sw_bls12381.G2Affine, // Public Input
	pk *sw_bls12381.G1Affine, // Public Input
	u *sw_bls12381.G1Affine, // Public Input
	v [32]byte, // Public Input
	w [32]byte, // Public Input
	c *big.Int, // Commitment (MiMC sum)
	ctxHi *big.Int, // Context Hash Hi
	ctxLo *big.Int, // Context Hash Lo
) error {
	// 1. Get embedded VK
	vk, err := getEmbeddedVK()
	if err != nil {
		return fmt.Errorf("failed to load embedded VK: %w", err)
	}

	// 2. Build public witness
	// Convert byte arrays to [32]uints.U8
	vArr := [32]uints.U8{}
	wArr := [32]uints.U8{}
	for i := 0; i < 32; i++ {
		vArr[i] = uints.NewU8(v[i])
		wArr[i] = uints.NewU8(w[i])
	}

	// Decompose Qid (G2Affine) into emulated elements
	// Qid is G2 (E2 x, E2 y). E2 is (A0, A1).
	// Circuit fields: QidX0, QidX1, QidY0, QidY1
	qidX0 := emulated.ValueOf[sw_bls12381.BaseField](qid.P.X.A0)
	qidX1 := emulated.ValueOf[sw_bls12381.BaseField](qid.P.X.A1)
	qidY0 := emulated.ValueOf[sw_bls12381.BaseField](qid.P.Y.A0)
	qidY1 := emulated.ValueOf[sw_bls12381.BaseField](qid.P.Y.A1)

	// PK (G1)
	pkX := emulated.ValueOf[sw_bls12381.BaseField](pk.X)
	pkY := emulated.ValueOf[sw_bls12381.BaseField](pk.Y)

	// U (G1)
	uX := emulated.ValueOf[sw_bls12381.BaseField](u.X)
	uY := emulated.ValueOf[sw_bls12381.BaseField](u.Y)

	// Commitment C (Variable)
	// CtxHi, CtxLo (Variable)

	publicWitness := &Circuit{
		QidX0: qidX0,
		QidX1: qidX1,
		QidY0: qidY0,
		QidY1: qidY1,
		PKX:   pkX,
		PKY:   pkY,
		UX:    uX,
		UY:    uY,
		V:     vArr,
		W:     wArr,
		C:     c,
		CtxHi: ctxHi,
		CtxLo: ctxLo,
	}

	// 3. Create Witness
	// Note: We only set Public fields. Secret fields (R2, Sigma, H3Count) are zero/nil.
	pubWitness, err := frontend.NewWitness(publicWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness creation failed: %w", err)
	}

	// 4. Deserialize proof
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return fmt.Errorf("proof deserialization failed: %w", err)
	}

	// 5. Verify
	if err := groth16.Verify(proof, vk, pubWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// GetEmbeddedCircuitID returns the circuit ID
func GetEmbeddedCircuitID() string {
	return CircuitID
}
