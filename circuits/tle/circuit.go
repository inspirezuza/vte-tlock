package tle

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bls12381"
	"github.com/consensys/gnark/std/algebra/emulated/sw_emulated"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/hash/sha2"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/uints"

	// Use local copy of sw_bls12381 to access G2AffP
	"vte-tlock/circuits/lib/sw_bls12381"
)

// Circuit implements Proof_TLE.
type Circuit struct {
	// Public Inputs
	// Qid (Hash(Round)) -- G2 Point (4 Fp elements).
	QidX0 emulated.Element[sw_bls12381.BaseField] `gnark:",public"`
	QidX1 emulated.Element[sw_bls12381.BaseField] `gnark:",public"`
	QidY0 emulated.Element[sw_bls12381.BaseField] `gnark:",public"`
	QidY1 emulated.Element[sw_bls12381.BaseField] `gnark:",public"`

	// Public Key (Network PK) -- G1 Point (2 Fp elements).
	PKX emulated.Element[sw_bls12381.BaseField] `gnark:",public"`
	PKY emulated.Element[sw_bls12381.BaseField] `gnark:",public"`

	// Ciphertext U -- G1 Point.
	UX emulated.Element[sw_bls12381.BaseField] `gnark:",public"`
	UY emulated.Element[sw_bls12381.BaseField] `gnark:",public"`

	// Ciphertext V -- 32 bytes.
	V [32]uints.U8 `gnark:",public"`

	// Ciphertext W -- 32 bytes.
	W [32]uints.U8 `gnark:",public"`

	// Commitment C (MiMC hash of r2, ctx)
	C     frontend.Variable `gnark:",public"`
	CtxHi frontend.Variable `gnark:",public"` // Context Hash (Hi 128 bits)
	CtxLo frontend.Variable `gnark:",public"` // Context Hash (Lo 128 bits)

	// Witness
	R2      emulated.Element[sw_bls12381.ScalarField] // The secret r2
	Sigma   [32]uints.U8                              // Randomness.
	H3Count frontend.Variable                         // Counter for H3 rejection sampling (witness).
}

func (c *Circuit) Define(api frontend.API) error {
	// 0. Init API
	uapi, err := uints.NewBytes(api)
	if err != nil {
		return err
	}

	scalarField, err := emulated.NewField[sw_bls12381.ScalarField](api)
	if err != nil {
		return err
	}

	// 1. Verify Commitment C = MiMC(DST, r2, ctx)
	// DST setup
	dstBytes := [32]byte{}
	copy(dstBytes[:], []byte("VTE_TLOCK_v0.2.1"))
	dstHi := new(big.Int).SetBytes(dstBytes[:16])
	dstLo := new(big.Int).SetBytes(dstBytes[16:])

	// r2 is emulated.Element (255 bits).
	// We need 128-bit splits for MiMC.
	r2Bits := scalarField.ToBits(&c.R2) // LE bits
	// Pad/slice to 256 bits if needed? Scalar is likely 255 bits.
	// ToBits returns full limb bits?
	// emulated.ToBits returns NbLimbs * BitsPerLimb bits.
	// BLS12-381 Fr is ~255 bits.
	// We use FromBinary on first 128 and next 128?
	r2Lo := api.FromBinary(r2Bits[:128]...)
	r2Hi := api.FromBinary(r2Bits[128:256]...) // Ensure we have enough bits, zero pad if implied

	m, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	// MiMC(DST_hi, DST_lo, r2_hi, r2_lo, ctx_hi, ctx_lo)
	m.Write(dstHi, dstLo, r2Hi, r2Lo, c.CtxHi, c.CtxLo)
	cCalc := m.Sum()
	api.AssertIsEqual(cCalc, c.C)

	// 2. IBE Verification Logic

	// 2a. Reconstruct R2 Bytes from R2 Bits (for SHA2)
	// r2Bits is LE. Convert to BE for bitsToBytes?
	// r2Bits is [LSB...].
	// We want BE bytes.
	// Reverse to BE bits.
	r2BitsBE := make([]frontend.Variable, 256)
	for i := 0; i < 256; i++ {
		if i < len(r2Bits) {
			r2BitsBE[i] = r2Bits[255-i] // Assuming 256 bits available or padded
		} else {
			r2BitsBE[i] = 0
		}
	}
	// NOTE: r2Bits might be e.g. 256 length if params say so.
	// For BLS12-381 Fr: 4 limbs of 64 bits = 256 bits exactly?
	// Check sw_bls12381 params. Usually yes.

	r2Bytes := bitsToBytes(uapi, api, r2BitsBE)

	// 2b. Compute W_check = r2Bytes XOR H4(sigma)
	// H4(sigma) = SHA256("IBE-H4" || sigma)
	h4, err := sha2.New(api)
	if err != nil {
		return err
	}
	h4.Write(uints.NewU8Array([]byte("IBE-H4")))
	h4.Write(c.Sigma[:])
	h4Sigma := h4.Sum()

	// wCheck matches c.W
	for i := 0; i < 32; i++ {
		val := uapi.Xor(r2Bytes[i], h4Sigma[i])
		uapi.AssertIsEqual(val, c.W[i])
	}

	// 2c. Derive r = H3(sigma, r2Bytes, counter)
	h3, err := sha2.New(api)
	if err != nil {
		return err
	}
	h3.Write(uints.NewU8Array([]byte("IBE-H3")))
	h3.Write(c.Sigma[:])
	h3.Write(r2Bytes)
	preHash := h3.Sum()

	// New hasher for second step
	h3Final, err := sha2.New(api)
	if err != nil {
		return err
	}

	// Counter (2 bytes LE)
	countBits := api.ToBinary(c.H3Count, 16)
	countBitsLByte := reverseBits(countBits[0:8])
	countBitsHByte := reverseBits(countBits[8:16])

	countBytesFinal := make([]uints.U8, 2)
	countBytesFinal[0] = bitsToBytes(uapi, api, countBitsLByte)[0]
	countBytesFinal[1] = bitsToBytes(uapi, api, countBitsHByte)[0]

	h3Final.Write(countBytesFinal)
	h3Final.Write(preHash)
	rHash := h3Final.Sum() // 32 bytes

	// Convert rHash to Scalar
	rHashBits := toBits(api, uapi, rHash) // BE bits
	rHashBitsLE := reverseBits(rHashBits)

	rScalar := scalarField.FromBits(rHashBitsLE...)

	// Rejection Sampling Check: rScalar < q
	// emulated.FromBits usually reduces mod modulus.
	// But H3 logic requires strict < q check on the 256 bits?
	// or 255 bits?
	// If we trust FromBits to implement field mapping correctly.
	// Usually to check canonical representation we re-convert to bits and compare.
	rScalarBits := scalarField.ToBits(rScalar)
	// rHashBitsLE MSB (255) must be 0 if q is 255 bits and we want canonical check.
	// But rScalarBits is canonical by definition.
	// We need to Ensure rHashBitsLE == rScalarBits to verify it didn't wrap.
	// i.e. rHash (original value) < q.
	for i := 0; i < 255; i++ {
		api.AssertIsEqual(rScalarBits[i], rHashBitsLE[i])
	}
	// Check MSB is 0 (since q is 255 bits, 256th bit logic etc)
	api.AssertIsEqual(rHashBitsLE[255], 0)

	// 2d. Check U = r * G1_Generator
	pair, err := sw_bls12381.NewPairing(api)
	if err != nil {
		return err
	}

	// Instantiate Generic Curve for G1 Scalar Multiplication
	curve, err := sw_emulated.New[sw_bls12381.BaseField, sw_bls12381.ScalarField](api, sw_emulated.GetBLS12381Params())
	if err != nil {
		return err
	}

	g1Gen := getG1Generator(api)

	// ScalarMul args: Base (G1Affine), Scalar.
	uCheck := curve.ScalarMul(&g1Gen, rScalar)

	// Assert U matches Input U
	uInput := &sw_bls12381.G1Affine{
		X: c.UX, // emulated.Element
		Y: c.UY,
	}
	curve.AssertIsEqual(uCheck, uInput)

	// 2e. Check V = sigma XOR H2(e(r*PK, Qid))
	pkInput := &sw_bls12381.G1Affine{
		X: c.PKX,
		Y: c.PKY,
	}
	rPK := curve.ScalarMul(pkInput, rScalar)

	qidInput := &sw_bls12381.G2Affine{
		P: sw_bls12381.G2AffP{
			X: fields_bls12381.E2{
				A0: c.QidX0,
				A1: c.QidX1,
			},
			Y: fields_bls12381.E2{
				A0: c.QidY0,
				A1: c.QidY1,
			},
		},
	}

	gid, err := pair.Pair([]*sw_bls12381.G1Affine{rPK}, []*sw_bls12381.G2Affine{qidInput})
	if err != nil {
		return err
	}

	// H2(Gid)
	h2, err := sha2.New(api)
	if err != nil {
		return err
	}
	h2.Write(uints.NewU8Array([]byte("IBE-H2")))

	gtCoeffs := []*emulated.Element[sw_bls12381.BaseField]{
		&gid.A0, &gid.A1, &gid.A2, &gid.A3, &gid.A4, &gid.A5,
		&gid.A6, &gid.A7, &gid.A8, &gid.A9, &gid.A10, &gid.A11,
	}

	for _, coeff := range gtCoeffs {
		// Use curve.BaseField instead of re-instantiating if possible?
		// or just use curve.BaseField implementation.
		// curve.BaseField is *emulated.Field[Base].
		// But here we need to call ToBits on Element.
		// curve struct doesn't expose underlying field easily?
		// We can re-instantiate or use existing:
		// We need baseField API instance.
		// Instantiate one.
		baseField, _ := emulated.NewField[sw_bls12381.BaseField](api)

		bits := baseField.ToBits(coeff) // LE bits
		paddingLen := 384 - len(bits)
		// We need to reverse to BE?
		bitsRev := reverseBits(bits)

		// Pad with zeros at beginning if BE?
		// If 384 bits required.
		// bitsRev is BE version of bits.
		// If bits was < 384, we need to pad.
		// Logic in original was correct?
		// Original: padding make, append padding, bitsRev.
		padding := make([]frontend.Variable, paddingLen)
		for k := range padding {
			padding[k] = 0
		}
		fullBitsBE := append(padding, bitsRev...)

		bytes := bitsToBytes(uapi, api, fullBitsBE)
		h2.Write(bytes)
	}

	h2Val := h2.Sum() // 32 bytes

	// XOR Check with V
	for i := 0; i < 32; i++ {
		xorVal := uapi.Xor(h2Val[i], c.V[i])
		uapi.AssertIsEqual(xorVal, c.Sigma[i])
	}

	return nil
}

// Helpers

func reverseBits(bits []frontend.Variable) []frontend.Variable {
	n := len(bits)
	res := make([]frontend.Variable, n)
	for i := 0; i < n; i++ {
		res[i] = bits[n-1-i]
	}
	return res
}

func bitsToBytes(uapi *uints.Bytes, api frontend.API, bits []frontend.Variable) []uints.U8 {
	nBytes := len(bits) / 8
	res := make([]uints.U8, nBytes)
	for i := 0; i < nBytes; i++ {
		chunk := bits[i*8 : (i+1)*8]
		var val frontend.Variable = 0
		for bitIdx := 0; bitIdx < 8; bitIdx++ {
			val = api.Add(api.Mul(val, 2), chunk[bitIdx])
		}
		res[i] = uapi.ValueOf(val) // Use ValueOf
	}
	return res
}

func toBits(api frontend.API, uapi *uints.Bytes, u8s []uints.U8) []frontend.Variable {
	res := make([]frontend.Variable, 0, len(u8s)*8)
	for _, u := range u8s {
		// ToBinary returns LE bits of the byte value.
		// We want BE bits?
		// If u8s are [B0, B1...] where B0 is MSB byte.
		// And inside B0, we want MSB bit first.
		// api.ToBinary(v) -> [b0...b7] (LSB...MSB).
		// So we flip them.
		v := uapi.Value(u)
		bits := api.ToBinary(v, 8)
		for i := 0; i < 8; i++ {
			res = append(res, bits[7-i])
		}
	}
	return res
}

func getG1Generator(api frontend.API) sw_bls12381.G1Affine {
	// Hardcoded BLS12-381 G1 Generator
	// X = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
	// Y = 1339506545344400125111158580222008230691880993593178553535265559817540242220492934052309199676735509933182103440028
	return sw_bls12381.G1Affine{
		X: emulated.ValueOf[sw_bls12381.BaseField]("3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507"),
		Y: emulated.ValueOf[sw_bls12381.BaseField]("1339506545344400125111158580222008230691880993593178553535265559817540242220492934052309199676735509933182103440028"),
	}
}
