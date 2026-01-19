package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"syscall/js"

	"vte-tlock/pkg/vte"
)

// decryptVTE decrypts a VTE package and returns the plaintext secret
// Args: pkgJSON (string)
// Returns: {plaintext: base64, error?: string}
func decryptVTE(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return errorResponse("missing package JSON argument")
	}

	pkgJSON := args[0].String()

	var pkg vte.VTEPackage
	if err := json.Unmarshal([]byte(pkgJSON), &pkg); err != nil {
		return errorResponse(fmt.Sprintf("invalid package JSON: %v", err))
	}

	// Call real decryption
	ctx := context.Background()
	result, err := vte.DecryptVTE(ctx, &pkg)
	if err != nil {
		return errorResponse(fmt.Sprintf("decryption failed: %v", err))
	}

	// Return plaintext as base64
	return map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(result.R2),
	}
}
