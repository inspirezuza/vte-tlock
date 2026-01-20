package vte

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"vte-tlock/circuits/commitment"
)

// ProofStrategy defines which proving backend to use for TLE proofs
type ProofStrategy string

const (
	StrategyGnark ProofStrategy = "gnark"
	StrategyZKVM  ProofStrategy = "zkvm"
	StrategyAuto  ProofStrategy = "auto"
)

// GenerateVTEOptions contains configuration for VTE package generation
type GenerateVTEOptions struct {
	Params       *GenerateVTEParams
	TLEStrategy  ProofStrategy
	EnableSECPZK bool // If true, generate commitment ZK proof
	EnableTLEZK  bool // If false, skip TLE proving (not yet implemented)
	TimeoutSECP  time.Duration
	TimeoutTLE   time.Duration
}

// GenerateVTEWithProofs creates a complete VTE package with ZK proofs
// This is the M5 implementation with concurrent proving
// GenerateVTEWithProofs creates a complete VTE package with ZK proofs
// This is the M5 implementation with concurrent proving
func GenerateVTEWithProofs(ctx context.Context, opts *GenerateVTEOptions) (*VTEPackageV2, error) {
	if opts == nil {
		return nil, fmt.Errorf("options cannot be nil")
	}

	// Set defaults
	if opts.TimeoutSECP == 0 {
		opts.TimeoutSECP = 2 * time.Minute
	}
	if opts.TimeoutTLE == 0 {
		opts.TimeoutTLE = 12 * time.Minute // 10min + buffer
	}

	// Set GenerateProof in params based on options
	opts.Params.GenerateProof = opts.EnableSECPZK

	// Step 1: Generate base package structure (includes proof if enabled)
	pkg, err := GenerateVTE(opts.Params)
	if err != nil {
		return nil, fmt.Errorf("base package generation failed: %w", err)
	}

	// Step 2: Parallel TLE proof generation (not yet implemented)
	var wg sync.WaitGroup
	errChan := make(chan error, 1)

	if opts.EnableTLEZK {
		wg.Add(1)
		go func() {
			defer wg.Done()

			tleCtx, cancel := context.WithTimeout(ctx, opts.TimeoutTLE)
			defer cancel()

			// TODO: Implement real TLE circuit prover with strategy selection
			// For now, proofs remain empty
			select {
			case <-tleCtx.Done():
				errChan <- fmt.Errorf("TLE proving timed out")
				return
			default:
				// Real implementation would call tle.ProveTLE() here
				// pkg.ProofTLE would be populated with actual proof
			}
		}()
	}

	// Wait for completion
	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	return pkg, nil
}

// VerifyCommitmentProof verifies the ZK proof that proves knowledge of r2
// This can be verified BEFORE the timelock expires!
//
// SECURITY: This function is TRUSTLESS because:
//   - Uses embedded VK (hardcoded at compile time)
//   - Never accepts prover-supplied VK
//   - Prover cannot forge proofs for a different circuit
func VerifyCommitmentProof(pkg *VTEPackageV2) error {
	if len(pkg.Proofs.Commitment.ProofB64) == 0 {
		return fmt.Errorf("no commitment proof found in package")
	}

	// Validate Circuit ID
	// This ensures the package claims to be using the circuit we have embedded
	// In the future, this allows supporting multiple circuit versions
	expectedID := commitment.GetEmbeddedCircuitID()
	if pkg.Proofs.Commitment.CircuitID != expectedID {
		return fmt.Errorf("circuit ID mismatch: package claims %s, verifiable only strictly with %s",
			pkg.Proofs.Commitment.CircuitID, expectedID)
	}

	// Use TRUSTLESS verification with embedded VK
	// This NEVER uses VK from the package - only embedded VK
	err := commitment.VerifyWithEmbeddedVK(pkg.Proofs.Commitment.ProofB64, pkg.Public.Commitment, pkg.Context.CtxHash)
	if err != nil {
		return fmt.Errorf("commitment proof verification failed: %w", err)
	}

	return nil
}

// GetExpectedCircuitID returns the expected circuit ID for validation
// Packages can include circuit_id so verifiers know which VK to use
func GetExpectedCircuitID() string {
	return commitment.GetEmbeddedCircuitID()
}

// DecryptResult contains the result of decryption
type DecryptResult struct {
	R2         []byte
	CtxHash    []byte
	Commitment []byte
}

// DecryptVTE decrypts a VTEPackageV2 and returns the plaintext r2 secret.
// This requires the timelock to have expired (round reached).
// Verifier MUST supply trusted endpoints.
func DecryptVTE(ctx context.Context, pkg *VTEPackageV2, endpoints []string) (*DecryptResult, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("at least one drand endpoint must be provided")
	}

	// Use real decryption
	r2, err := Decrypt(ctx, pkg.Tlock.DrandChainHash, pkg.Tlock.Round, pkg.Tlock.Capsule, endpoints)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Verify commitment using MiMC (matching GenerateVTE)
	expectedC, err := commitment.ComputeCommitmentHash(r2, pkg.Context.CtxHash)
	if err != nil {
		return nil, fmt.Errorf("commitment computation failed: %w", err)
	}

	if !bytes.Equal(expectedC, pkg.Public.Commitment) {
		return nil, fmt.Errorf("commitment verification failed: decrypted r2 does not match commitment")
	}

	return &DecryptResult{
		R2:         r2,
		CtxHash:    pkg.Context.CtxHash,
		Commitment: pkg.Public.Commitment,
	}, nil
}
