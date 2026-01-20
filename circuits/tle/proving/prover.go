package proving

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	"vte-tlock/circuits/lib/sw_bls12381"
	"vte-tlock/circuits/tle"
)

// embeddedPKCache caches the deserialized embedded PK
var (
	embeddedPKCache groth16.ProvingKey
	embeddedPKOnce  sync.Once
	embeddedPKErr   error
)

// getEmbeddedPK returns the deserialized embedded PK (cached)
func getEmbeddedPK() (groth16.ProvingKey, error) {
	embeddedPKOnce.Do(func() {
		if len(EmbeddedPK) == 0 {
			embeddedPKErr = fmt.Errorf("embedded PK is empty - check pk_embed.go")
			return
		}

		embeddedPKCache = groth16.NewProvingKey(ecc.BN254)
		_, embeddedPKErr = embeddedPKCache.ReadFrom(bytes.NewReader(EmbeddedPK))
		if embeddedPKErr != nil {
			embeddedPKErr = fmt.Errorf("failed to deserialize embedded PK: %w", embeddedPKErr)
		}
	})
	return embeddedPKCache, embeddedPKErr
}

// WitnessInput contains all inputs needed to generate a TLE proof.
// Caller must capture these values during encryption.
type WitnessInput struct {
	// Public
	Qid   *sw_bls12381.G2Affine
	PK    *sw_bls12381.G1Affine
	U     *sw_bls12381.G1Affine
	V     [32]byte
	W     [32]byte
	C     *big.Int
	CtxHi *big.Int
	CtxLo *big.Int

	// Secret
	R2      *big.Int // The secret r2 scalar
	Sigma   [32]byte // The random seed sigma
	H3Count uint64   // The counter for rejection sampling
}

// Prove generates a TLE proof using ONLY the embedded PK.
func Prove(input *WitnessInput) ([]byte, error) {
	pk, err := getEmbeddedPK()
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded PK: %w", err)
	}

	// Build Witness
	vArr := [32]uints.U8{}
	wArr := [32]uints.U8{}
	sigmaArr := [32]uints.U8{}
	for i := 0; i < 32; i++ {
		vArr[i] = uints.NewU8(input.V[i])
		wArr[i] = uints.NewU8(input.W[i])
		sigmaArr[i] = uints.NewU8(input.Sigma[i])
	}

	// Compile circuit to get CCS (Constraint System)
	// This takes ~5-10s for 1.6M constraints
	var c tle.Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, fmt.Errorf("circuit compilation failed: %w", err)
	}

	circuit := &tle.Circuit{
		// Public
		QidX0: emulated.ValueOf[sw_bls12381.BaseField](input.Qid.P.X.A0),
		QidX1: emulated.ValueOf[sw_bls12381.BaseField](input.Qid.P.X.A1),
		QidY0: emulated.ValueOf[sw_bls12381.BaseField](input.Qid.P.Y.A0),
		QidY1: emulated.ValueOf[sw_bls12381.BaseField](input.Qid.P.Y.A1),
		PKX:   emulated.ValueOf[sw_bls12381.BaseField](input.PK.X),
		PKY:   emulated.ValueOf[sw_bls12381.BaseField](input.PK.Y),
		UX:    emulated.ValueOf[sw_bls12381.BaseField](input.U.X),
		UY:    emulated.ValueOf[sw_bls12381.BaseField](input.U.Y),
		V:     vArr,
		W:     wArr,
		C:     input.C,
		CtxHi: input.CtxHi,
		CtxLo: input.CtxLo,

		// Secret
		R2:      emulated.ValueOf[sw_bls12381.ScalarField](input.R2),
		Sigma:   sigmaArr,
		H3Count: input.H3Count,
	}

	witness, err := frontend.NewWitness(circuit, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness creation failed: %w", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("proving failed: %w", err)
	}

	var buf bytes.Buffer
	_, err = proof.WriteTo(&buf)
	if err != nil {
		return nil, fmt.Errorf("proof serialization failed: %w", err)
	}

	return buf.Bytes(), nil
}
