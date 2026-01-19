package commitment

import (
	"bytes"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ProverResult contains proving metrics and the proof artifact
type ProverResult struct {
	Proof       []byte
	ProvingTime time.Duration
	Constraints int
	Success     bool
	ErrorMsg    string
}

// ProvingKeys holds Groth16 keys for commitment circuit
type ProvingKeys struct {
	PK  groth16.ProvingKey
	VK  groth16.VerifyingKey
	CCS constraint.ConstraintSystem
}

var (
	cachedKeys *ProvingKeys
	keysMutex  sync.Mutex
)

// DST is the domain separation tag for commitment
const DSTValue = "12345678901234567890"

// Setup performs trusted setup for commitment circuit (cached)
func Setup() (*ProvingKeys, error) {
	keysMutex.Lock()
	defer keysMutex.Unlock()

	if cachedKeys != nil {
		return cachedKeys, nil
	}

	var c Circuit

	// Compile circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, fmt.Errorf("commitment circuit compilation failed: %w", err)
	}

	// Groth16 setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("groth16 setup failed: %w", err)
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
	C       []byte // 32 bytes (commitment)
}

// ComputeCommitmentHash computes C = MiMC(DST, r2, ctx_hash)
// This must match what the circuit computes
func ComputeCommitmentHash(r2, ctxHash []byte) ([]byte, error) {
	// Convert to field elements
	var r2Fe, ctxFe, dstFe fr.Element
	r2Fe.SetBytes(r2)
	ctxFe.SetBytes(ctxHash)
	dstFe.SetString(DSTValue)

	// Compute MiMC hash
	h := mimc.NewMiMC()
	h.Write(dstFe.Marshal())
	h.Write(r2Fe.Marshal())
	h.Write(ctxFe.Marshal())

	return h.Sum(nil), nil
}

// Prove generates a commitment proof
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

	// Convert inputs to field elements
	r2BigInt := new(big.Int).SetBytes(input.R2)
	ctxBigInt := new(big.Int).SetBytes(input.CtxHash)
	cBigInt := new(big.Int).SetBytes(input.C)

	// Build witness
	witness := &Circuit{
		CtxHash: ctxBigInt,
		C:       cBigInt,
		R2:      r2BigInt,
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

// Verify verifies a commitment proof
func Verify(keys *ProvingKeys, proofBytes []byte, input *WitnessInput) error {
	if keys == nil {
		var err error
		keys, err = Setup()
		if err != nil {
			return err
		}
	}

	// Convert public inputs
	ctxBigInt := new(big.Int).SetBytes(input.CtxHash)
	cBigInt := new(big.Int).SetBytes(input.C)

	// Public witness only (no secret r2)
	publicWitness := &Circuit{
		CtxHash: ctxBigInt,
		C:       cBigInt,
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
