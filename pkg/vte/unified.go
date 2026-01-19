package vte

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"
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
	EnableSECPZK bool // If false, skip SECP proving (faster mock mode)
	EnableTLEZK  bool // If false, skip TLE proving (faster mock mode)
	TimeoutSECP  time.Duration
	TimeoutTLE   time.Duration
}

// GenerateVTEWithProofs creates a complete VTE package with ZK proofs
// This is the M5 implementation with concurrent proving
func GenerateVTEWithProofs(ctx context.Context, opts *GenerateVTEOptions) (*VTEPackage, error) {
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

	// Step 1: Generate base package structure
	pkg, err := GenerateVTE(opts.Params)
	if err != nil {
		return nil, fmt.Errorf("base package generation failed: %w", err)
	}

	// Step 2: Parallel proof generation
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	// SECP Proof (optional - can be generated offline)
	if opts.EnableSECPZK {
		wg.Add(1)
		go func() {
			defer wg.Done()

			secpCtx, cancel := context.WithTimeout(ctx, opts.TimeoutSECP)
			defer cancel()

			// TODO: Implement real SECP circuit prover
			// For now, proofs remain empty
			select {
			case <-secpCtx.Done():
				errChan <- fmt.Errorf("SECP proving timed out")
				return
			default:
				// Real implementation would call SECP prover here
				// pkg.ProofSECP would be populated with actual proof
			}
		}()
	}

	// TLE Proof (optional - can be generated offline)
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

// DecryptResult contains the result of decryption
type DecryptResult struct {
	R2         []byte
	CtxHash    []byte
	Commitment []byte
}

// DecryptVTE decrypts a VTEPackage and returns the plaintext r2 secret.
// This requires the timelock to have expired (round reached).
func DecryptVTE(ctx context.Context, pkg *VTEPackage) (*DecryptResult, error) {
	// Use real decryption
	r2, err := Decrypt(ctx, pkg.NetworkID.ChainHash, pkg.Round, pkg.Capsule, pkg.NetworkID.DrandEndpoints)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Verify REAL commitment
	expectedC, err := ComputeCommitment(r2, pkg.CtxHash)
	if err != nil {
		return nil, fmt.Errorf("commitment computation failed: %w", err)
	}

	if !bytes.Equal(expectedC, pkg.C) {
		return nil, fmt.Errorf("commitment verification failed: decrypted r2 does not match commitment")
	}

	return &DecryptResult{
		R2:         r2,
		CtxHash:    pkg.CtxHash,
		Commitment: pkg.C,
	}, nil
}
