package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"syscall/js"

	"vte-tlock/pkg/vte"
)

// Wrapper for exposing functions to JS
func verifyVTE(this js.Value, args []js.Value) interface{} {
	if len(args) < 5 {
		return map[string]interface{}{"error": "insufficient arguments"}
	}

	var pkg vte.VTEPackage
	err := json.Unmarshal([]byte(args[0].String()), &pkg)
	if err != nil {
		return errorResponse("failed to unmarshal package: " + err.Error())
	}

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

	err = vte.VerifyVTE(&pkg, round, chainHash, formatID, ctxHash)
	if err != nil {
		return map[string]interface{}{"success": false, "error": err.Error()}
	}

	return map[string]interface{}{"success": true}
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

	return map[string]interface{}{
		"ephemeral_pub_key": hex.EncodeToString(fields.EphemeralPubKey),
		"tag":               hex.EncodeToString(fields.Tag),
		"ciphertext_len":    len(fields.Ciphertext),
	}
}

func generateVTE(this js.Value, args []js.Value) interface{} {
	if len(args) < 7 {
		return errorResponse("insufficient arguments (need 7: round, chainHash, formatID, r2, ctxHash, endpoints, strategy)")
	}

	round := uint64(args[0].Int())
	chainHash, _ := hex.DecodeString(args[1].String())
	formatID := args[2].String()
	r2, _ := hex.DecodeString(args[3].String())
	ctxHash, _ := hex.DecodeString(args[4].String())

	// endpoints is a js.Value array
	jsEndpoints := args[5]
	endpoints := make([]string, jsEndpoints.Length())
	for i := 0; i < jsEndpoints.Length(); i++ {
		endpoints[i] = jsEndpoints.Index(i).String()
	}

	// strategy (gnark|zkvm|auto)
	strategyStr := args[6].String()

	// Generate package
	pkg, err := vte.GenerateVTE(&vte.GenerateVTEParams{
		Round:          round,
		ChainHash:      chainHash,
		FormatID:       formatID,
		R2:             r2,
		CtxHash:        ctxHash,
		DrandEndpoints: endpoints,
	})
	if err != nil {
		return errorResponse(err.Error())
	}

	// Annotate package with strategy metadata (mock for now)
	pkg.ProofTLE = []byte(fmt.Sprintf("mock_strategy_%s", strategyStr))

	pkgBytes, _ := json.Marshal(pkg)
	return string(pkgBytes)
}

func computeCtxHash(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return errorResponse("args: sessionID, refundTxHex")
	}
	h, err := vte.ComputeCtxHash(args[0].String(), args[1].String())
	if err != nil {
		return errorResponse(err.Error())
	}
	return hex.EncodeToString(h)
}

func errorResponse(msg string) map[string]interface{} {
	return map[string]interface{}{"error": msg}
}

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("verifyVTE", js.FuncOf(verifyVTE))
	js.Global().Set("parseCapsule", js.FuncOf(parseCapsule))
	js.Global().Set("generateVTE", js.FuncOf(generateVTE))
	js.Global().Set("computeCtxHash", js.FuncOf(computeCtxHash))
	js.Global().Set("decryptVTE", js.FuncOf(decryptVTE))
	<-c
}
