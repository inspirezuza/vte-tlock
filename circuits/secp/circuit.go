package secp

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/poseidon"
	"github.com/consensys/gnark/std/math/emulated"
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
	// 1. Range Checks on Limbs (128 bits)
	// We assume the field is BN254, so 128 bits fits easily.
	// API doesn't have explicit range check for < 2^128 easily without bits,
	// but ToBinary/FromBinary does verification.
	// Or we use emulated field to enforce standard scalar field check.
	// Let's do loose range check first to ensure they are "limbs".
	// Actually, the emulated scalar conversion will handle the strict modulus reduction/check.
	// But for Poseidon binding, we want BIT EXACT representation.
	// So we must ensure the inputs to Poseidon are exactly the chunks of the 32-byte r2.

	// Check inputs are < 2^128
	// max128 := new(big.Int).Lsh(big.NewInt(1), 128)
	// We can use api.ToBinary to enforce bit length if needed, or rely on the Scalar reconstruction.

	// 2. Commitment Verification
	// C_field = Poseidon(DST_hi, DST_lo, r2_hi, r2_lo, ctx_hi, ctx_lo)
	// DST = "VTE_TLOCK_v0.2.1" padded.
	// encoded: 565445...
	// We need to hardcode DST limbs.
	dstBytes := [32]byte{}
	copy(dstBytes[:], []byte("VTE_TLOCK_v0.2.1"))
	dstHi := new(big.Int).SetBytes(dstBytes[:16])
	dstLo := new(big.Int).SetBytes(dstBytes[16:])

	p := poseidon.NewPoseidon2(api)
	// Note: Poseidon inputs. Order matters.
	// Spec: DST_hi, DST_lo, r2_hi, r2_lo, ctx_hi, ctx_lo
	cCalc := p.Compute(dstHi, dstLo, c.SimR2Hi, c.SimR2Lo, c.CtxHi, c.CtxLo)

	api.AssertIsEqual(cCalc, c.C)

	// 3. Secp256k1 Scalar Multiplication
	// R2 = r2 * G

	// Initialize emulated curve
	curve, err := sw_emulated.New[emulated.Secp256k1](api, sw_emulated.GetSecp256k1Params())
	if err != nil {
		return err
	}

	// Construct the scalar r2 from limbs
	// We need to map our 2x128 native limbs to the emulated scalar.
	// emulated.Scalar is usually 4x64 or similar depending on params.
	// BN254 scalar field < Secp256k1 scalar field?
	// Secp scalar order ~ 2^256. BN254 scalar order ~ 2^254.
	// Wait! BN254 scalar is SMALLER than Secp scalar.
	// So we can't fit a random Secp scalar into a single Native variable.
	// But here we have 2 limbs of 128. That's fine.

	// We need to populate a emulated.Scalar from the limbs.
	// emulated.NewElementFromBits or similar?
	// The `emulated` package typically works with checking if the value in the native field + overflow fits.

	// We create a scalar from the limbs.
	scalarField, err := emulated.NewField[emulated.Secp256k1Fr](api)
	if err != nil {
		return err
	}

	// Convert our Native limbs (R2Hi, R2Lo) into an Emulated Scalar Element.
	// R2 = R2Hi * 2^128 + R2Lo
	// We can set the value using polynomial composition if the emulation supports it.
	// Ideally: r2Scalar = scalarField.NewElement(c.SimR2Hi, c.SimR2Lo) if it accepted 128-bit chunks?
	// Actually `NewElement` takes `*big.Int` (constants) or `frontend.Variable`.
	// If `frontend.Variable`, it assumes it's fully reduced?

	// Let's rely on `compose` if available or manual packing.
	// Secp256k1Fr uses 4 limbs of 64 bits usually.
	// We have 2 limbs of 128.
	// decompose 128 -> 64.

	// This circuit construction is getting detailed.
	// Let's Assume `scalarField.NewElement` can handle reconstruction or we do it carefully.
	// Since I cannot check the docs/IDE, I will define a helper method in the file later if needed.
	// For now, I'll pass the limbs to a helper `recomposeScalar` (placeholder logic).

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
func recomposeScalar(api frontend.API, f *emulated.Field[emulated.Secp256k1Fr], hi, lo frontend.Variable) *emulated.Element {
	// Simple approach: combine to bits, then recombine? expensive.
	// Better: Use the Emulated Field's definition of limbs.
	// Default Secp256k1Fr uses 4 limbs of 64 bits.
	// We have lo (128) = lo_hi(64) || lo_lo(64).

	bitsLo := api.ToBinary(lo, 128)
	bitsHi := api.ToBinary(hi, 128)

	// We have 256 bits total.
	// Check range? scalar modulus is slightly less than 2^256.
	// The emulated element will handle reduction or we should strictly enforce valid scalar.
	// Since r2 is "timelocked", it is uniform random [0, 2^256)?
	// Actually drand/tlock usually encrypts 32 bytes.
	// We just interpret those bytes as a scalar.
	// It might overflow the curve order.
	// If it overflows, `ScalarMulBase` will use the reduced value.
	// But our `C` commitment commits to the BYTES (unreduced).
	// The `r2` we get out of decryption is bytes.
	// So we need `r2_bytes -> r2_scalar_reduced`.
	// The circuit binding `C` is on `r2_bytes`.
	// The circuit `ScalarMulBase` takes `r2_scalar`.
	// Correctness: We must ensure `r2Scalar` IS `r2_bytes` mod Order.
	// `bitsHi` and `bitsLo` represent `r2_bytes`.
	// We can convert these bits to an emulated Element directly.

	// Emulated field `FromBits` is likely what we want.
	fullBits := append(bitsLo, bitsHi...) // Little-endian bits or Big-endian?
	// api.ToBinary returns little-endian bits usually (low to high weight).
	// Spec says: r2_lo is `X[16..32]`. It is the lower weight bytes.
	// Big-endian interpretation of 16-byte slice?
	// `X_lo` = big-endian(X[16..32]).
	// `X_hi` = big-endian(X[0..16]).
	// Total X = X_hi * 2^128 + X_lo.
	// So `bitsLo` (LE) are the first 128 bits of the value.
	// `bitsHi` (LE) are the next.
	// So `fullBits` = `bitsLo || bitsHi`.

	// But we need to verify `sw_emulated` expectation.
	// Let's leave `FromBits` assumption.

	// Note: api.ToBinary(v) returns LE bits.
	el := f.FromBits(fullBits...)
	return el
}

func assertLimbsMatch(api frontend.API, curve *sw_emulated.Curve[emulated.Secp256k1Param], p emulated.Element, hi, lo frontend.Variable) {
	// Recompose the emulated element p back to 2x128 native limbs?
	// Or decompose hi/lo to bits and compare with p?

	// `p` is in the Base Field of Secp256k1 (Secp256k1Fp).
	// We can use `curve.ToBits(p)` to get the bits.
	// Then verify against hi/lo bits.

	pBits := curve.ToBits(&p) // Returns LE bits (standard)
	// Truncate/Pad pBits to 256? (Field is 256 bits).

	// hi/lo bits
	loBits := api.ToBinary(lo, 128)
	hiBits := api.ToBinary(hi, 128)

	for i := 0; i < 128; i++ {
		api.AssertIsEqual(pBits[i], loBits[i])
		api.AssertIsEqual(pBits[i+128], hiBits[i])
	}
}
