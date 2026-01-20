//go:build js && wasm
// +build js,wasm

package vte

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/drand/drand/v2/common"
	"github.com/drand/drand/v2/crypto"
	"github.com/drand/kyber"
	"github.com/drand/tlock"
)

var _ tlock.Network = (*WasmNetwork)(nil)

// ChainInfoJSON is the structure returned by drand API /info endpoint
type ChainInfoJSON struct {
	PublicKey   string `json:"public_key"`
	Period      int64  `json:"period"`
	GenesisTime int64  `json:"genesis_time"`
	Hash        string `json:"hash"`
	SchemeID    string `json:"schemeID"`
}

type WasmNetwork struct {
	chainHash   string
	scheme      *crypto.Scheme
	pubKey      kyber.Point
	genesisTime int64
	period      time.Duration

	// Pre-fetched beacon (optional, for sync operation)
	prefetchedBeacon *common.Beacon
}

// NewNetwork creates a network client from pre-fetched chain info JSON
// This avoids HTTP calls from WASM which cause deadlocks
func NewNetwork(endpoint, chainHash string) (tlock.Network, error) {
	// In WASM, we need the chain info to be passed in
	// This function should not be called directly in WASM
	// Use NewNetworkFromChainInfo instead
	return nil, fmt.Errorf("NewNetwork cannot perform HTTP in WASM - use NewNetworkFromChainInfo with pre-fetched data")
}

// NewNetworkFromChainInfo creates a network from pre-fetched chain info
func NewNetworkFromChainInfo(chainInfoJSON string, chainHash string) (tlock.Network, error) {
	var info ChainInfoJSON
	if err := json.Unmarshal([]byte(chainInfoJSON), &info); err != nil {
		return nil, fmt.Errorf("failed to parse chain info: %w", err)
	}

	// Get cryptographic scheme
	scheme, err := crypto.SchemeFromName(info.SchemeID)
	if err != nil {
		return nil, fmt.Errorf("unknown scheme: %s: %w", info.SchemeID, err)
	}

	// Parse public key from hex
	pubKeyBytes, err := hex.DecodeString(info.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key hex: %w", err)
	}

	pubKey := scheme.KeyGroup.Point()
	if err := pubKey.UnmarshalBinary(pubKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public key: %w", err)
	}

	return &WasmNetwork{
		chainHash:   chainHash,
		scheme:      scheme,
		pubKey:      pubKey,
		genesisTime: info.GenesisTime,
		period:      time.Duration(info.Period) * time.Second,
	}, nil
}

// SetPrefetchedBeacon allows setting a pre-fetched beacon to avoid Request() HTTP
func (w *WasmNetwork) SetPrefetchedBeacon(round uint64, signatureHex string) error {
	sigBytes, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	w.prefetchedBeacon = &common.Beacon{
		Round:     round,
		Signature: sigBytes,
	}
	return nil
}

func (w *WasmNetwork) ChainHash() string { return w.chainHash }

func (w *WasmNetwork) Current(t time.Time) uint64 {
	genesis := time.Unix(w.genesisTime, 0)
	if t.Before(genesis) {
		return 0
	}
	elapsed := t.Sub(genesis)
	if w.period == 0 {
		return 0
	}
	return uint64(elapsed / w.period)
}

func (w *WasmNetwork) PublicKey() kyber.Point { return w.pubKey }

func (w *WasmNetwork) Scheme() crypto.Scheme { return *w.scheme }

func (w *WasmNetwork) Signature(round uint64) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

func (w *WasmNetwork) SwitchChainHash(h string) error {
	w.chainHash = h
	return nil
}

func (w *WasmNetwork) Request(ctx context.Context, round uint64) (common.Beacon, error) {
	// Use prefetched beacon if available
	if w.prefetchedBeacon != nil && w.prefetchedBeacon.Round == round {
		return *w.prefetchedBeacon, nil
	}
	// Cannot make HTTP requests from WASM - beacon must be pre-fetched
	return common.Beacon{}, fmt.Errorf("beacon not prefetched for round %d - WASM cannot make HTTP requests", round)
}
