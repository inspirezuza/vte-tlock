//go:build !js || !wasm
// +build !js !wasm

package vte

import (
	"bytes"
	"context"
	"fmt"

	"github.com/drand/tlock"
)

// Encrypt encrypts the payload (r2) for a specific round and network.
// It requires the ChainHash (bytes) and the Network Config (endpoints).
// It connects to the first available endpoint to fetch valid network info.
func Encrypt(ctx context.Context, chainHash []byte, round uint64, payload []byte, endpoints []string) ([]byte, error) {
	if len(payload) != 32 {
		return nil, fmt.Errorf("payload (r2) must be exactly 32 bytes")
	}

	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no drand endpoints provided")
	}

	chainHashHex := fmt.Sprintf("%x", chainHash)

	// Create network client using the appropriate implementation (WASM or Native)
	network, err := NewNetwork(endpoints[0], chainHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to create network client for %s: %w", endpoints[0], err)
	}

	// Create tlock client using Strict mode (although beneficial for Decrypt, helps intent).
	client := tlock.New(network).Strict()

	var buf bytes.Buffer
	src := bytes.NewReader(payload)

	// Encrypt
	if err := client.Encrypt(&buf, src, round); err != nil {
		return nil, fmt.Errorf("tlock encryption failed: %w", err)
	}

	return buf.Bytes(), nil
}

// EncryptWithPrefetch is a stub for native builds - it just calls Encrypt.
// In native builds we can make HTTP requests, so prefetch is not needed.
func EncryptWithPrefetch(ctx context.Context, chainHash []byte, round uint64, payload []byte, chainInfoJSON string, beaconSignature string) ([]byte, error) {
	// Native builds don't need prefetch - just use the default Encrypt
	// which can make HTTP requests directly
	return nil, fmt.Errorf("EncryptWithPrefetch should not be called in native builds - use Encrypt instead")
}
