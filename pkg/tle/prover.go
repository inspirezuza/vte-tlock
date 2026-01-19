package tle

import (
	"fmt"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ProofStrategy defines which proving system to use
type ProofStrategy string

const (
	StrategyGnark ProofStrategy = "gnark" // Track A: Gnark BN254
	StrategyZKVM  ProofStrategy = "zkvm"  // Track B: ZKVM (SP1/Risc0)
	StrategyAuto  ProofStrategy = "auto"  // Auto-select based on constraints
)

// ProverResult contains proving metrics and the proof artifact
type ProverResult struct {
	Proof       []byte
	ProvingTime time.Duration
	Constraints int
	Strategy    ProofStrategy
	Success     bool
	ErrorMsg    string
}

// ProvingKeys holds the Groth16 proving/verifying keys (Track A only)
type ProvingKeys struct {
	PK groth16.ProvingKey
	VK groth16.VerifyingKey
}

// SetupTrackA performs Groth16 trusted setup for the TLE circuit
// This is expensive and should be cached
func SetupTrackA() (*ProvingKeys, error) {
	var circuit Circuit

	// Compile
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("circuit compilation failed: %w", err)
	}

	// Setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("groth16 setup failed: %w", err)
	}

	return &ProvingKeys{PK: pk, VK: vk}, nil
}

// ProveTrackA generates a TLE proof using Gnark (Track A)
func ProveTrackA(keys *ProvingKeys, witness *Circuit) (*ProverResult, error) {
	startTime := time.Now()
	result := &ProverResult{Strategy: StrategyGnark}

	// Compile circuit (for constraint counting)
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	if err != nil {
		result.ErrorMsg = err.Error()
		return result, err
	}
	result.Constraints = ccs.GetNbConstraints()

	// Create witness
	fullWitness, err := frontend.NewWitness(witness, ecc.BN254.ScalarField())
	if err != nil {
		result.ErrorMsg = err.Error()
		return result, err
	}

	// Prove
	proof, err := groth16.Prove(ccs, keys.PK, fullWitness)
	if err != nil {
		result.ErrorMsg = err.Error()
		return result, err
	}

	// Serialize proof
	proofBytes, err := proof.MarshalBinary()
	if err != nil {
		result.ErrorMsg = err.Error()
		return result, err
	}

	result.Proof = proofBytes
	result.ProvingTime = time.Since(startTime)
	result.Success = true

	return result, nil
}

// VerifyTrackA verifies a TLE proof using Gnark (Track A)
func VerifyTrackA(keys *ProvingKeys, proofBytes []byte, publicWitness frontend.Witness) error {
	// Deserialize proof
	proof := groth16.NewProof(ecc.BN254)
	if err := proof.UnmarshalBinary(proofBytes); err != nil {
		return fmt.Errorf("failed to unmarshal proof: %w", err)
	}

	// Verify
	if err := groth16.Verify(proof, keys.VK, publicWitness); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// ProveTrackB generates a TLE proof using ZKVM (Track B)
// TODO: Implement SP1/Risc0 integration
func ProveTrackB(witness *Circuit) (*ProverResult, error) {
	result := &ProverResult{
		Strategy:    StrategyZKVM,
		Success:     false,
		ErrorMsg:    "Track B (ZKVM) not yet implemented",
		Constraints: 0, // ZKVM doesn't have R1CS constraints
	}

	// Placeholder for ZKVM proving logic
	// When implemented, this will:
	// 1. Serialize witness to guest program
	// 2. Run SP1/Risc0 prover
	// 3. Return proof + metrics

	return result, fmt.Errorf("ZKVM proving not implemented")
}

// ProveTLE is the unified interface that selects the proving strategy
func ProveTLE(keys *ProvingKeys, witness *Circuit, strategy ProofStrategy) (*ProverResult, error) {
	if strategy == StrategyAuto {
		// Auto-select: Default to Gnark for now
		// In production, this would check constraint count and decide
		strategy = StrategyGnark
	}

	switch strategy {
	case StrategyGnark:
		return ProveTrackA(keys, witness)
	case StrategyZKVM:
		return ProveTrackB(witness)
	default:
		return nil, fmt.Errorf("unknown proof strategy: %s", strategy)
	}
}
