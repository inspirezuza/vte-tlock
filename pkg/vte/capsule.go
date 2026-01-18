package vte

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"filippo.io/age/armor"
)

// ParseCapsule extracts the binding fields from the capsule based on the format ID.
// This is critical for Proof_TLE binding.
func ParseCapsule(capsule []byte, formatID string) (CipherFields, error) {
	switch formatID {
	case "tlock_v1_age_pairing":
		return parseTlockV1(capsule)
	default:
		return CipherFields{}, fmt.Errorf("%w: %s", ErrFormatMismatch, formatID)
	}
}

// parseTlockV1 parses the drand tlock v1 format (age encrypted).
func parseTlockV1(capsule []byte) (CipherFields, error) {
	// 1. Handle Armor if present
	var reader io.Reader = bytes.NewReader(capsule)
	bufReader := bufio.NewReader(reader)
	// We handle errors from Peek purely by ignoring armor if peek fails (unlikely for valid slice)
	if peek, _ := bufReader.Peek(len(armor.Header)); string(peek) == armor.Header {
		reader = armor.NewReader(bufReader)
	} else {
		reader = bufReader
	}

	// 2. Read all data (after armor decoding)
	data, err := io.ReadAll(reader)
	if err != nil {
		return CipherFields{}, err
	}

	// 3. Parse Age Header manually to find tlock stanza
	// Age header consists of lines ending with "---".
	// We need to be careful: the "---" line might contain the MAC.
	// We iterate lines.

	// Convert data to string for header parsing (header is ASCII)
	// But payload is binary, so we must be careful with indices.
	// Strategy: find the end of header first.
	// The header ends with a line starting with "---".

	const headerEndMarker = "\n---"
	headerEndIndex := bytes.Index(data, []byte(headerEndMarker))
	if headerEndIndex == -1 {
		// Attempt to see if it's "---" at start (unlikely) or just ---
		if bytes.HasPrefix(data, []byte("---")) {
			headerEndIndex = 0 // The start is the end marker? Invalid age file usually starts with version.
		} else {
			return CipherFields{}, fmt.Errorf("invalid age format: no header end marker")
		}
	}

	headerBytes := data[:headerEndIndex]

	// Find the newline after the MAC to get payload start
	// The line starting with --- continues until newline.
	// data[headerEndIndex] is '\n'.
	// data[headerEndIndex+1] is '-'.

	payloadStartIndex := -1
	// Search for newline after headerEndIndex + len(headerEndMarker)
	// headerEndMarker is 4 chars.
	startSearch := headerEndIndex + len(headerEndMarker)
	if startSearch >= len(data) {
		// Truncated?
		// Maybe no MAC? Age spec says MAC is there.
	} else {
		newlineAfterMac := bytes.IndexByte(data[startSearch:], '\n')
		if newlineAfterMac != -1 {
			payloadStartIndex = startSearch + newlineAfterMac + 1
		}
	}

	if payloadStartIndex == -1 || payloadStartIndex > len(data) {
		return CipherFields{}, fmt.Errorf("could not find payload start")
	}

	payload := data[payloadStartIndex:]

	// 4. Parse Header Stanzas
	headerStr := string(headerBytes)
	lines := strings.Split(headerStr, "\n")

	var stanzaBody []byte
	var foundStanza bool

	for i, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-> tlock") {
			// Found it.
			// args := strings.Split(line, " ")
			// args[2] is round, args[3] is chainhash

			// Body is next line(s).
			if i+1 >= len(lines) {
				return CipherFields{}, fmt.Errorf("truncated stanza body")
			}

			bodyB64 := strings.TrimSpace(lines[i+1])
			decoded, err := base64.RawStdEncoding.DecodeString(bodyB64)
			if err != nil {
				return CipherFields{}, fmt.Errorf("invalid base64 in stanza: %w", err)
			}
			stanzaBody = decoded
			foundStanza = true
			break // Assuming only one tlock stanza
		}
	}

	if !foundStanza {
		return CipherFields{}, fmt.Errorf("no tlock stanza found in header")
	}

	// 5. Split Stanza Body (U || V || W)
	// U is variable length?
	// V and W are 16 bytes.
	if len(stanzaBody) < 32 {
		return CipherFields{}, fmt.Errorf("stanza body too short for V+W")
	}

	uLen := len(stanzaBody) - 32
	u := stanzaBody[:uLen]
	v := stanzaBody[uLen : uLen+16]
	w := stanzaBody[uLen+16:]

	return CipherFields{
		EphemeralPubKey: u,
		Mask:            v,
		Tag:             w,
		Ciphertext:      payload,
	}, nil
}
