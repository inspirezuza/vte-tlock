package commitment

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit proves knowledge of r2 such that:
// C = MiMC(DST, r2, ctx_hash)
//
// This circuit demonstrates the prover knows the secret r2 value
// that produces the public commitment C. Since R2 = r2 * G is computed
// outside the circuit and verified separately, this proof binds the
// commitment to the secret scalar.
//
// MiMC is used instead of Poseidon for simplicity and gnark compatibility.
type Circuit struct {
	// Public Inputs
	// Context hash (32 bytes as single BN254 field element)
	CtxHash frontend.Variable `gnark:",public"`

	// C is the commitment (MiMC output)
	C frontend.Variable `gnark:",public"`

	// Secret Witness: r2 (32 bytes as single BN254 field element)
	R2 frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	// DST as field element (hash of "VTE_COMMIT_V2")
	// Precomputed: SHA256("VTE_COMMIT_V2") mod BN254_Fr
	// For simplicity, we use a fixed constant
	dst := big.NewInt(0)
	dst.SetString("12345678901234567890", 10) // Domain separator constant

	// Create MiMC hasher (native BN254 support)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash: DST || r2 || ctx_hash
	h.Write(dst)
	h.Write(c.R2)
	h.Write(c.CtxHash)
	cCalc := h.Sum()

	// Assert commitment matches
	api.AssertIsEqual(cCalc, c.C)

	return nil
}
