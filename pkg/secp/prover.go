package secp

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	circuit "vte-tlock/circuits/secp"
)

// ProverResult contains proving metrics and the proof artifact
type ProverResult struct {
	Proof       []byte
	ProvingTime time.Duration
	Constraints int
	Success     bool
	ErrorMsg    string
}

// ProvingKeys holds Groth16 keys for SECP circuit
type ProvingKeys struct {
	PK  groth16.ProvingKey
	VK  groth16.VerifyingKey
	CCS constraint.ConstraintSystem
}

var (
	cachedKeys *ProvingKeys
	keysMutex  sync.Mutex
	keysOnce   sync.Once
)

// Setup performs trusted setup for SECP circuit (cached)
func Setup() (*ProvingKeys, error) {
	keysMutex.Lock()
	defer keysMutex.Unlock()

	if cachedKeys != nil {
		return cachedKeys, nil
	}

	var c circuit.Circuit

	// Compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, fmt.Errorf("SECP circuit compilation failed: %w", err)
	}

	// Groth16 setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("SECP groth16 setup failed: %w", err)
	}

	cachedKeys = &ProvingKeys{
		PK:  pk,
		VK:  vk,
		CCS: ccs,
	}

	return cachedKeys, nil
}

// WitnessInput contains the values for proof generation
type WitnessInput struct {
	// Secret witness: r2 scalar (32 bytes, big-endian)
	R2 []byte

	// Public inputs
	CtxHash []byte // 32 bytes
	C       []byte // 32 bytes (Poseidon commitment)
	R2x     []byte // 32 bytes (R2 point x coordinate)
	R2y     []byte // 32 bytes (R2 point y coordinate)
}

// Prove generates a SECP proof that r2 is the discrete log of R2
// and that C = Poseidon(DST, r2, ctx_hash)
func Prove(keys *ProvingKeys, input *WitnessInput) (*ProverResult, error) {
	startTime := time.Now()
	result := &ProverResult{}

	if keys == nil {
		var err error
		keys, err = Setup()
		if err != nil {
			result.ErrorMsg = err.Error()
			return result, err
		}
	}

	result.Constraints = keys.CCS.GetNbConstraints()

	// Parse inputs into circuit format
	r2Hi, r2Lo := splitTo128BitLimbs(input.R2)
	ctxHi, ctxLo := splitTo128BitLimbs(input.CtxHash)
	r2xHi, r2xLo := splitTo128BitLimbs(input.R2x)
	r2yHi, r2yLo := splitTo128BitLimbs(input.R2y)

	// Commitment as field element
	cBigInt := new(big.Int).SetBytes(input.C)

	// Build witness
	witness := &circuit.Circuit{
		// Public inputs
		CtxHi: ctxHi,
		CtxLo: ctxLo,
		C:     cBigInt,
		R2xHi: r2xHi,
		R2xLo: r2xLo,
		R2yHi: r2yHi,
		R2yLo: r2yLo,
		// Secret witness
		SimR2Hi: r2Hi,
		SimR2Lo: r2Lo,
	}

	// Create full witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("witness creation failed: %v", err)
		return result, err
	}

	// Generate proof
	proof, err := groth16.Prove(keys.CCS, keys.PK, fullWitness)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("proof generation failed: %v", err)
		return result, err
	}

	// Serialize proof
	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	if err != nil {
		result.ErrorMsg = fmt.Sprintf("proof serialization failed: %v", err)
		return result, err
	}

	result.Proof = proofBuf.Bytes()
	result.ProvingTime = time.Since(startTime)
	result.Success = true

	return result, nil
}

// Verify verifies a SECP proof
func Verify(keys *ProvingKeys, proofBytes []byte, input *WitnessInput) error {
	if keys == nil {
		var err error
		keys, err = Setup()
		if err != nil {
			return err
		}
	}

	// Parse inputs for public witness
	ctxHi, ctxLo := splitTo128BitLimbs(input.CtxHash)
	r2xHi, r2xLo := splitTo128BitLimbs(input.R2x)
	r2yHi, r2yLo := splitTo128BitLimbs(input.R2y)
	cBigInt := new(big.Int).SetBytes(input.C)

	// Public witness only (no secret r2)
	publicWitness := &circuit.Circuit{
		CtxHi: ctxHi,
		CtxLo: ctxLo,
		C:     cBigInt,
		R2xHi: r2xHi,
		R2xLo: r2xLo,
		R2yHi: r2yHi,
		R2yLo: r2yLo,
	}

	pubWitness, err := frontend.NewWitness(publicWitness, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("public witness creation failed: %w", err)
	}

	// Deserialize proof
	proof := groth16.NewProof(ecc.BN254)
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return fmt.Errorf("proof deserialization failed: %w", err)
	}

	// Verify
	if err := groth16.Verify(proof, keys.VK, pubWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// splitTo128BitLimbs splits a 32-byte value into Hi and Lo 128-bit limbs
func splitTo128BitLimbs(data []byte) (*big.Int, *big.Int) {
	if len(data) != 32 {
		// Pad or truncate
		padded := make([]byte, 32)
		copy(padded[32-len(data):], data)
		data = padded
	}

	hi := new(big.Int).SetBytes(data[:16])
	lo := new(big.Int).SetBytes(data[16:])
	return hi, lo
}

// GetVerifyingKeyBytes returns serialized verifying key for embedding
func GetVerifyingKeyBytes() ([]byte, error) {
	keys, err := Setup()
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	_, err = keys.VK.WriteTo(&buf)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
