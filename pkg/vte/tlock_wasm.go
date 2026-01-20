//go:build js && wasm
// +build js,wasm

package vte

import (
	"bytes"
	"context"
	"fmt"

	"github.com/drand/tlock"
)

// Encrypt encrypts the payload (r2) for a specific round using pre-fetched chain info.
// This WASM version uses NewNetworkFromChainInfo to avoid HTTP calls in WASM.
func Encrypt(ctx context.Context, chainHash []byte, round uint64, payload []byte, endpoints []string) ([]byte, error) {
	return nil, fmt.Errorf("Encrypt requires pre-fetched data in WASM (CACHE CHECK) - use EncryptWithPrefetch instead")
}

// EncryptWithPrefetch encrypts using pre-fetched chain info.
// NOTE: For ENCRYPTION, the beacon is NOT needed - only the chain's public key is required.
// The beacon is only needed for DECRYPTION after the round has passed.
// This allows encrypting for FUTURE rounds.
func EncryptWithPrefetch(ctx context.Context, chainHash []byte, round uint64, payload []byte, chainInfoJSON string, beaconSignature string) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload (r2) must be exactly 32 bytes")
	}

	chainHashHex := fmt.Sprintf("%x", chainHash)

	// Create network from pre-fetched chain info
	network, err := NewNetworkFromChainInfo(chainInfoJSON, chainHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to create network from chain info: %w", err)
	}

	// NOTE: We do NOT set the beacon for encryption!
	// tlock.Encrypt only needs the chain's public key (from chain info).
	// The beacon is only used for DECRYPTION.
	// This allows encrypting for future rounds that haven't occurred yet.

	// Create tlock client
	client := tlock.New(network).Strict()

	var buf bytes.Buffer
	src := bytes.NewReader(payload)

	// Encrypt - this only uses public key, not beacon
	if err := client.Encrypt(&buf, src, round); err != nil {
		return nil, fmt.Errorf("tlock encryption failed: %w", err)
	}

	return buf.Bytes(), nil
}
