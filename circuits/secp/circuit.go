package secp

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/poseidon2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
)

// Circuit implements the Proof_SECP logic.
type Circuit struct {
	// Public Inputs
	// CtxHash is split into 2 x 128-bit limbs
	CtxHi frontend.Variable `gnark:",public"`
	CtxLo frontend.Variable `gnark:",public"`

	// C is the commitment field element (Poseidon output)
	C frontend.Variable `gnark:",public"`

	// R2 Public Key (Lockpoint), split into 2x128-bit limbs per coordinate
	R2xHi frontend.Variable `gnark:",public"`
	R2xLo frontend.Variable `gnark:",public"`
	R2yHi frontend.Variable `gnark:",public"`
	R2yLo frontend.Variable `gnark:",public"`

	// Secret Witness: r2 (scalar), split into 2x128-bit limbs
	SimR2Hi frontend.Variable
	SimR2Lo frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	// ... (Range checks implicit in conversion)

	// 2. Commitment Verification
	dstBytes := [32]byte{}
	copy(dstBytes[:], []byte("VTE_TLOCK_v0.2.1"))
	dstHi := new(big.Int).SetBytes(dstBytes[:16])
	dstLo := new(big.Int).SetBytes(dstBytes[16:])

	p, err := poseidon2.NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}
	p.Write(dstHi, dstLo, c.SimR2Hi, c.SimR2Lo, c.CtxHi, c.CtxLo)
	cCalc := p.Sum()

	api.AssertIsEqual(cCalc, c.C)

	// 3. Secp256k1 Scalar Multiplication
	// R2 = r2 * G

	// Initialize emulated curve
	// [Base, Scalar] = [emparams.Secp256k1Fp, emparams.Secp256k1Fr]
	curve, err := sw_emulated.New[emparams.Secp256k1Fp, emparams.Secp256k1Fr](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}

	// We create a scalar from the limbs.
	scalarField, err := emulated.NewField[emparams.Secp256k1Fr](api)
	if err != nil {
		return err
	}

	r2Scalar := recomposeScalar(api, scalarField, c.SimR2Hi, c.SimR2Lo)

	// Base G interaction
	// R2 = r2 * G
	R2Point := curve.ScalarMulBase(r2Scalar)

	// 4. Verify R2 == Public Inputs
	// R2Point is emulated.Affince (X, Y).
	// We need to compare R2Point.X with (R2xHi, R2xLo) and same for Y.

	assertLimbsMatch(api, curve, R2Point.X, c.R2xHi, c.R2xLo)
	assertLimbsMatch(api, curve, R2Point.Y, c.R2yHi, c.R2yLo)

	return nil
}

// recomposeScalar converts 2x128 native limbs to an emulated scalar.
func recomposeScalar(api frontend.API, f *emulated.Field[emparams.Secp256k1Fr], hi, lo frontend.Variable) *emulated.Element[emparams.Secp256k1Fr] {
	bitsLo := api.ToBinary(lo, 128)
	bitsHi := api.ToBinary(hi, 128)

	// Emulated field `FromBits` is likely what we want.
	fullBits := append(bitsLo, bitsHi...)

	el := f.FromBits(fullBits...)
	return el
}

func assertLimbsMatch(api frontend.API, curve *sw_emulated.Curve[emparams.Secp256k1Fp, emparams.Secp256k1Fr], p emulated.Element[emparams.Secp256k1Fp], hi, lo frontend.Variable) {
	// `p` is in the Base Field of Secp256k1 (Secp256k1Fp).
	// We can use `curve.baseApi.ToBits(p)` or accessing baseApi directly via curve.
	// Actually `curve` struct hides `baseApi` as private field?
	// It has `scalarApi` and `baseApi` as private.
	// But it might export helpers.
	// Wait, `curve.baseApi` is used in methods inside `point.go`.
	// Is it exported? No, generic struct fields are unexported `baseApi`.

	// BUT, `p` is an `emulated.Element[Base]`.
	// We can use a fresh `emulated.Field[Base]` to get bits if we want, OR
	// verify if `sw_emulated` exposes something.

	// `curve` does NOT expose `ToBits`.
	// However, we can instantiate the field again or just use `p`.
	// Wait, `p` is linked to the API.

	// Better: `emulated.NewField[emparams.Secp256k1Fp](api)` and use it.

	f, _ := emulated.NewField[emparams.Secp256k1Fp](api)
	pBits := f.ToBits(&p) // Returns LE bits (standard)

	// hi/lo bits
	loBits := api.ToBinary(lo, 128)
	hiBits := api.ToBinary(hi, 128)

	for i := 0; i < 128; i++ {
		api.AssertIsEqual(pBits[i], loBits[i])
		api.AssertIsEqual(pBits[i+128], hiBits[i])
	}
}
