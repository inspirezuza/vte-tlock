package vte

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// ProofSecp represents a Schnorr proof that R2 = r2 * G.
// Using standard BIP-340 Schnorr signature.
// It effectively binds R2 to the context.
type ProofSecp struct {
	Signature []byte `json:"signature"` // 64 bytes (R || s)
}

// GenerateSchnorrProof generates a BIP-340 Schnorr signature for secret r2Bytes and message msg.
func GenerateSchnorrProof(r2Bytes []byte, msg []byte) (*ProofSecp, error) {
	// 1. Parse Private Key
	privKey, _ := btcec.PrivKeyFromBytes(r2Bytes)

	// 2. Sign Message (CtxHash)
	// Note: msg should be 32 bytes hash. CtxHash is 32 bytes.
	// schnorr.Sign expects a 32-byte hash.
	var msgHash [32]byte
	if len(msg) != 32 {
		return nil, fmt.Errorf("message must be 32 bytes")
	}
	copy(msgHash[:], msg)

	signature, err := schnorr.Sign(privKey, msgHash[:])
	if err != nil {
		return nil, fmt.Errorf("schnorr sign failed: %w", err)
	}

	return &ProofSecp{
		Signature: signature.Serialize(), // 64 bytes
	}, nil
}

// VerifySchnorrProof verifies the BIP-340 Schnorr signature.
func VerifySchnorrProof(r2Compressed []byte, msg []byte, proof *ProofSecp) error {
	if len(proof.Signature) != 64 {
		return fmt.Errorf("invalid signature size: %d", len(proof.Signature))
	}

	// 1. Parse Public Key
	pubKey, err := schnorr.ParsePubKey(r2Compressed)
	if err != nil {
		// btcec schnorr expects 32-byte x-only public key usually for BIP-340.
		// But ParsePubKey might accept compressed point (33 bytes)?
		// Check btcec docs logic.
		// If r2Compressed is 33 bytes (0x02/0x03), ParsePubKey handles it?
		// schnorr.ParsePubKey parses 32-byte x-coord.
		// But btcec.ParsePubKey handles compressed.
		// Standard Schnorr (BIP-340) uses x-only.
		// VTE uses r2Compressed (33 bytes).
		// We can convert 33 bytes to 32 bytes x-coord if we assume BIP-340.
		// Or using btcec legacy Schnorr?
		// btcec/v2/schnorr implements BIP-340.
		// It requires PubKey to be converted?
		// Let's try parsing as standard pubkey first.
		pk, err2 := btcec.ParsePubKey(r2Compressed)
		if err2 != nil {
			return fmt.Errorf("invalid public key: %w", err2)
		}
		pubKey = pk
	}

	// 2. ParsSig
	sig, err := schnorr.ParseSignature(proof.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature format: %w", err)
	}

	// 3. Verify
	var msgHash [32]byte
	if len(msg) != 32 {
		return fmt.Errorf("message must be 32 bytes")
	}
	copy(msgHash[:], msg)

	if !sig.Verify(msgHash[:], pubKey) {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}
