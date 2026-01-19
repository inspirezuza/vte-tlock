package vte

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"
)

// DrandNetworkInfo contains timing parameters for a drand network
type DrandNetworkInfo struct {
	ChainHash   []byte
	GenesisTime int64 // Unix timestamp of round 1
	Period      int64 // Seconds between rounds
	SchemeID    string
}

// DefaultQuicknetInfo returns the drand Quicknet network parameters
// Quicknet: ~3 second rounds, good for testing
func DefaultQuicknetInfo() DrandNetworkInfo {
	chainHash, _ := hexDecode("52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971")
	return DrandNetworkInfo{
		ChainHash:   chainHash,
		GenesisTime: 1692803367, // August 23, 2023
		Period:      3,          // 3 seconds
		SchemeID:    "bls-unchained-g1-rfc9380",
	}
}

// TimeToRound calculates the drand round number for a given target time
func (n *DrandNetworkInfo) TimeToRound(targetTime time.Time) uint64 {
	targetUnix := targetTime.Unix()

	if targetUnix <= n.GenesisTime {
		return 1 // Minimum round
	}

	elapsed := targetUnix - n.GenesisTime
	round := uint64(elapsed / n.Period)

	return round + 1 // Round 1 is at genesis
}

// RoundToTime calculates the approximate time when a round will be available
func (n *DrandNetworkInfo) RoundToTime(round uint64) time.Time {
	if round <= 1 {
		return time.Unix(n.GenesisTime, 0)
	}

	elapsed := int64(round-1) * n.Period
	return time.Unix(n.GenesisTime+elapsed, 0)
}

// DurationToRound calculates the round number for "now + duration"
func (n *DrandNetworkInfo) DurationToRound(duration time.Duration) uint64 {
	targetTime := time.Now().Add(duration)
	return n.TimeToRound(targetTime)
}

// PlaintextToR2 converts a plaintext string to a 32-byte r2 value
// Uses SHA256 to ensure fixed length
func PlaintextToR2(plaintext string) []byte {
	h := sha256.Sum256([]byte(plaintext))
	return h[:]
}

// EncryptPlaintext is a convenience wrapper that encrypts plaintext with timelock
func EncryptPlaintext(plaintext string, targetTime time.Time, network DrandNetworkInfo) ([]byte, uint64, error) {
	// Convert plaintext to r2
	r2 := PlaintextToR2(plaintext)

	// Calculate round
	round := network.TimeToRound(targetTime)

	// Real tlock encryption
	capsule, err := Encrypt(context.Background(), network.ChainHash, round, r2, []string{"https://api.drand.sh"})
	if err != nil {
		return nil, 0, fmt.Errorf("encryption failed: %w", err)
	}

	return capsule, round, nil
}

func hexDecode(s string) ([]byte, error) {
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		fmt.Sscanf(s[i:i+2], "%02x", &b)
		result[i/2] = b
	}
	return result, nil
}
