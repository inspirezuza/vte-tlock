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
	if len(args) < 6 {
		return map[string]interface{}{"error": "insufficient arguments: pkg, round, chainHash, formatID, sessionID, refundTxHex"}
	}

	var pkg vte.VTEPackageV2
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
	sessionID := args[4].String()
	refundTx, err := hex.DecodeString(args[5].String())
	if err != nil {
		return errorResponse("invalid refund tx hex")
	}

	// VerifyVTE now takes structured params
	err = vte.VerifyVTE(&pkg, round, chainHash, formatID, sessionID, refundTx)
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
	if len(args) < 9 {
		return errorResponse("insufficient arguments: need round, chainHash, formatID, r2, refundTx, sessionID, endpoints, strategy, chainInfo")
	}

	round := uint64(args[0].Int())
	chainHash, _ := hex.DecodeString(args[1].String())
	formatID := args[2].String()
	r2, _ := hex.DecodeString(args[3].String())
	refundTx, _ := hex.DecodeString(args[4].String())
	sessionID := args[5].String()

	// 6: Active Endpoints (Proxy)
	jsEndpoints := args[6]
	endpoints := make([]string, jsEndpoints.Length())
	for i := 0; i < jsEndpoints.Length(); i++ {
		endpoints[i] = jsEndpoints.Index(i).String()
	}

	// 7: Strategy (ignored for now)
	// strategyStr := args[7].String()

	// 8: Chain Info JSON (pre-fetched for WASM)
	chainInfoJSON := args[8].String()
	if chainInfoJSON == "" {
		return errorResponse("WASM Error: ChainInfoJSON argument is empty. Ensure worker fetched it.")
	}

	// 9: Beacon Signature Hex
	beaconSignatureHex := ""
	if len(args) > 9 {
		beaconSignatureHex = args[9].String()
	}

	// Generate package
	pkg, err := vte.GenerateVTE(&vte.GenerateVTEParams{
		Round:              round,
		ChainHash:          chainHash,
		FormatID:           formatID,
		SessionID:          sessionID,
		R2:                 r2,
		RefundTx:           refundTx,
		DrandEndpoints:     endpoints, // Use proxy for encryption
		GenerateProof:      true,
		ChainInfoJSON:      chainInfoJSON,
		BeaconSignatureHex: beaconSignatureHex,
	})
	if err != nil {
		return errorResponse(err.Error())
	}

	// Annotate with TLE status if needed (schema has it as "not_implemented")

	pkgBytes, _ := json.Marshal(pkg)
	return string(pkgBytes)
}

func computeCtxHash(this js.Value, args []js.Value) interface{} {
	if len(args) < 5 {
		return errorResponse("args: sessionID, refundTxHex, chainHashHex, round, capsuleHashHex")
	}
	sessionID := args[0].String()
	refundTx, _ := hex.DecodeString(args[1].String())
	chainHash, _ := hex.DecodeString(args[2].String())
	round := uint64(args[3].Int())
	capsuleHash, _ := hex.DecodeString(args[4].String())

	params := &vte.CtxHashParams{
		SessionID:   sessionID,
		RefundTx:    refundTx,
		ChainHash:   chainHash,
		Round:       round,
		CapsuleHash: capsuleHash,
	}

	h, err := vte.ComputeFullCtxHash(params)
	if err != nil {
		return errorResponse(err.Error())
	}
	return hex.EncodeToString(h)
}

// computeR2Point computes R2 = r2 * G
// Takes r2 as hex string, returns compressed R2 (33 bytes) as hex
func computeR2Point(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorResponse("args: r2Hex")
	}

	r2Bytes, err := hex.DecodeString(args[0].String())
	if err != nil {
		return errorResponse("invalid r2 hex: " + err.Error())
	}

	compressed, err := vte.ComputeR2Point(r2Bytes)
	if err != nil {
		return errorResponse("failed to compute R2: " + err.Error())
	}

	return map[string]interface{}{
		"R2": hex.EncodeToString(compressed),
	}
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
	js.Global().Set("computeR2Point", js.FuncOf(computeR2Point))
	js.Global().Set("decryptVTE", js.FuncOf(decryptVTE))
	<-c
}
