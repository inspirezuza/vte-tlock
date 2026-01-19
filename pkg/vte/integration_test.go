package vte

import (
	"context"
	"testing"
	"time"
)

// TestRealEncryptDecryptFlow tests the complete flow with real tlock
// NOTE: This test requires internet connection (drand API) and takes time (beacon waiting)
// Skip this test for fast CI builds
func TestRealEncryptDecryptFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real drand test in short mode")
	}

	// Use Quicknet for fast testing (3s rounds)
	network := DefaultQuicknetInfo()

	plaintext := "Hello from real VTE-TLock!"

	// Encrypt for a round in near future (10 rounds ahead = 30 seconds)
	targetTime := time.Now().Add(30 * time.Second)
	capsule, round, err := EncryptPlaintext(plaintext, targetTime, network)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Encrypted for round %d, waiting for timelock...", round)

	// Wait for the round to be reached
	time.Sleep(35 * time.Second) // 30s + 5s buffer

	// Decrypt
	ctx := context.Background()
	r2, err := Decrypt(ctx, network.ChainHash, round, capsule, []string{"https://api.drand.sh"})
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify r2 matches our expected hash of plaintext
	expectedR2 := PlaintextToR2(plaintext)
	if string(r2) != string(expectedR2) {
		t.Fatalf("Decrypted r2 doesn't match. Got %x, want %x", r2, expectedR2)
	}

	t.Log("SUCCESS: Real encrypt/decrypt cycle completed!")
}

// TestGenerateVTERealEncryption tests GenerateVTE with real encryption
func TestGenerateVTERealEncryption(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping real drand test in short mode")
	}

	network := DefaultQuicknetInfo()
	targetTime := time.Now().Add(1 * time.Minute)
	round := network.TimeToRound(targetTime)

	params := &GenerateVTEParams{
		Round:          round,
		ChainHash:      network.ChainHash,
		FormatID:       "tlock_v1_age_pairing",
		R2:             PlaintextToR2("test secret"),
		CtxHash:        make([]byte, 32),
		DrandEndpoints: []string{"https://api.drand.sh"},
	}

	pkg, err := GenerateVTE(params)
	if err != nil {
		t.Fatalf("GenerateVTE failed: %v", err)
	}

	if len(pkg.Capsule) == 0 {
		t.Fatal("Expected real capsule, got empty")
	}

	if len(pkg.CipherFields.EphemeralPubKey) == 0 {
		t.Fatal("Expected parsed cipher fields, got empty EphemeralPubKey")
	}

	t.Logf("Generated VTE package with %d byte capsule", len(pkg.Capsule))
	t.Log("SUCCESS: Real VTE generation completed!")
}
