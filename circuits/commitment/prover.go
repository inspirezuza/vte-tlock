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

// Setup loads the embedded proving keys or generates new ones if not available
// IMPORTANT: For production, always use embedded keys from the same trusted setup
// to ensure proofs verify correctly
func Setup() (*ProvingKeys, error) {
	keysMutex.Lock()
	defer keysMutex.Unlock()

	if cachedKeys != nil {
		return cachedKeys, nil
	}

	// Try to load embedded keys first (from trusted setup)
	if len(EmbeddedPK) > 0 && len(EmbeddedVK) > 0 {
		return loadEmbeddedKeys()
	}

	// Fallback: generate new keys (only for development when keys don't exist yet)
	return generateNewKeys()
}

// loadEmbeddedKeys loads the pre-generated proving and verifying keys
func loadEmbeddedKeys() (*ProvingKeys, error) {
	// Compile circuit (needed for constraint system)
	var c Circuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		return nil, fmt.Errorf("circuit compilation failed: %w", err)
	}

	// Load embedded PK
	pk := groth16.NewProvingKey(ecc.BN254)
	_, err = pk.ReadFrom(bytes.NewReader(EmbeddedPK))
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded PK: %w", err)
	}

	// Load embedded VK
	vk := groth16.NewVerifyingKey(ecc.BN254)
	_, err = vk.ReadFrom(bytes.NewReader(EmbeddedVK))
	if err != nil {
		return nil, fmt.Errorf("failed to load embedded VK: %w", err)
	}

	cachedKeys = &ProvingKeys{
		PK:  pk,
		VK:  vk,
		CCS: ccs,
	}

	return cachedKeys, nil
}

// generateNewKeys generates new proving and verifying keys
// WARNING: This should only be used during development
// For production, run genkey first and use embedded keys
func generateNewKeys() (*ProvingKeys, error) {
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

// DST is the domain separation tag for commitment (SHA256 of "VTE_COMMIT_V2")
const DSTValue = "22834383894294698501250269098734612248590623067142646399676774643038477038930"

// WitnessInput contains the values for proof generation
type WitnessInput struct {
	// Secret witness: r2 scalar (32 bytes, big-endian)
	R2 []byte

	// Public inputs
	CtxHash []byte // 32 bytes
	C       []byte // 32 bytes (commitment)
}

// ComputeCommitmentHash computes C = MiMC(DST, r2_hi, r2_lo, ctx_hash)
// This must match what the circuit computes
func ComputeCommitmentHash(r2, ctxHash []byte) ([]byte, error) {
	// Convert to field elements
	var r2Hi, r2Lo, ctxFe, dstFe fr.Element
	ctxFe.SetBytes(ctxHash)
	dstFe.SetString(DSTValue)

	// Split r2 into two 128-bit limbs
	// r2 is 32 bytes. High 16 bytes -> r2Hi, Low 16 bytes -> r2Lo
	if len(r2) != 32 {
		return nil, fmt.Errorf("r2 must be 32 bytes")
	}
	r2Hi.SetBytes(r2[:16])
	r2Lo.SetBytes(r2[16:])

	// Compute MiMC hash
	h := mimc.NewMiMC()
	h.Write(dstFe.Marshal())
	h.Write(r2Hi.Marshal())
	h.Write(r2Lo.Marshal())
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

	// Convert inputs to field elements and split limbs
	if len(input.R2) != 32 {
		return nil, fmt.Errorf("R2 must be 32 bytes")
	}
	r2HiBigInt := new(big.Int).SetBytes(input.R2[:16])
	r2LoBigInt := new(big.Int).SetBytes(input.R2[16:])

	ctxBigInt := new(big.Int).SetBytes(input.CtxHash)
	cBigInt := new(big.Int).SetBytes(input.C)

	// Build witness
	witness := &Circuit{
		CtxHash: ctxBigInt,
		C:       cBigInt,
		R2Hi:    r2HiBigInt,
		R2Lo:    r2LoBigInt,
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
