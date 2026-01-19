package vte

import (
	"bytes"
	"context"
	"fmt"

	"github.com/drand/tlock"
	tlockHttp "github.com/drand/tlock/networks/http"
)

// Decrypt decrypts a tlock-encrypted capsule using the drand beacon for the specified round.
// It fetches the beacon from the drand network and uses it to decrypt the payload.
func Decrypt(ctx context.Context, chainHash []byte, round uint64, capsule []byte, endpoints []string) ([]byte, error) {
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no drand endpoints provided")
	}

	chainHashHex := fmt.Sprintf("%x", chainHash)

	// Create network client using the first endpoint
	network, err := tlockHttp.NewNetwork(endpoints[0], chainHashHex)
	if err != nil {
		return nil, fmt.Errorf("failed to create network client: %w", err)
	}

	// Create tlock client in strict mode
	client := tlock.New(network).Strict()

	// Decrypt using the capsule (capsule contains round info internally)
	var plaintext bytes.Buffer
	src := bytes.NewReader(capsule)

	if err := client.Decrypt(&plaintext, src); err != nil {
		return nil, fmt.Errorf("tlock decryption failed: %w", err)
	}

	return plaintext.Bytes(), nil
}
