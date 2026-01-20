package commitment

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

// Circuit proves knowledge of r2 such that:
// C = MiMC(DST, r2_hi, r2_lo, ctx_hash)
//
// This circuit demonstrates the prover knows the secret r2 value
// that produces the public commitment C.
//
// Hardening:
//  1. DST is derived from "VTE_COMMIT_V2"
//  2. R2 is split into two 128-bit limbs to prevent field modulus reduction issues
//     (since 32-byte r2 > BN254 scalar field modulus)
type Circuit struct {
	// Public Inputs
	// Context hash (32 bytes as single BN254 field element, assumed to fit or reduced)
	// For strictness we could split this too, but ctx_hash is public so less critical for hidden inputs
	CtxHash frontend.Variable `gnark:",public"`

	// C is the commitment (MiMC output)
	C frontend.Variable `gnark:",public"`

	// Secret Witness: r2 split into two 128-bit limbs
	// R2 = R2Hi * 2^128 + R2Lo (conceptually, though we just hash the limbs)
	R2Hi frontend.Variable
	R2Lo frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	// DST as field element (hash of "VTE_COMMIT_V2")
	// SHA256("VTE_COMMIT_V2") -> big.Int -> Field Element
	// 0x6e8e6b18... derived from echo -n "VTE_COMMIT_V2" | sha256sum
	dst := big.NewInt(0)
	dst.SetString("22834383894294698501250269098734612248590623067142646399676774643038477038930", 10)

	// Create MiMC hasher (native BN254 support)
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Hash: DST || r2_hi || r2_lo || ctx_hash
	h.Write(dst)
	h.Write(c.R2Hi)
	h.Write(c.R2Lo)
	h.Write(c.CtxHash)
	cCalc := h.Sum()

	// Assert commitment matches
	api.AssertIsEqual(cCalc, c.C)

	return nil
}
