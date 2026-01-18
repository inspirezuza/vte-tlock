package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"syscall/js"

	"vte-tlock/pkg/vte"
)

// Wrapper for exposing functions to JS
func verifyVTE(this js.Value, args []js.Value) interface{} {
	// Args:
	// 0: JSON string of VTEPackage
	// 1: round (int)
	// 2: chainhash (hex string)
	// 3: format_id (string)
	// 4: ctx_hash (hex string)

	if len(args) < 5 {
		return map[string]interface{}{
			"error": "insufficient arguments",
		}
	}

	// 1. Parse VTEPackage
	var pkg vte.VTEPackage
	err := json.Unmarshal([]byte(args[0].String()), &pkg)
	if err != nil {
		return errorResponse("failed to unmarshal package: " + err.Error())
	}

	// 2. Parse Inputs
	round := uint64(args[1].Int())
	chainHash, err := hex.DecodeString(args[2].String())
	if err != nil {
		return errorResponse("invalid chainhash hex")
	}
	formatID := args[3].String()
	ctxHashBytes, err := hex.DecodeString(args[4].String())
	if err != nil || len(ctxHashBytes) != 32 {
		return errorResponse("invalid ctx_hash hex")
	}
	var ctxHash [32]byte
	copy(ctxHash[:], ctxHashBytes)

	// 3. Verify
	err = vte.VerifyVTE(&pkg, round, chainHash, formatID, ctxHash)
	if err != nil {
		return map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		}
	}

	return map[string]interface{}{
		"success": true,
	}
}

func parseCapsule(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return errorResponse("args: capsuleBase64, formatID")
	}
	capsuleBytes, err := base64.StdEncoding.DecodeString(args[0].String())
	if err != nil {
		return errorResponse("invalid base64")
	}
	formatID := args[1].String()

	fields, err := vte.ParseCapsule(capsuleBytes, formatID)
	if err != nil {
		return errorResponse(err.Error())
	}

	// Return parsed fields as Map
	return map[string]interface{}{
		"ephemeral_pub_key": hex.EncodeToString(fields.EphemeralPubKey),
		"tag":               hex.EncodeToString(fields.Tag),
		"ciphertext_len":    len(fields.Ciphertext),
	}
}

func errorResponse(msg string) map[string]interface{} {
	return map[string]interface{}{
		"error": msg,
	}
}

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("verifyVTE", js.FuncOf(verifyVTE))
	js.Global().Set("parseCapsule", js.FuncOf(parseCapsule))
	<-c
}
