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
// Args: pkgJSON (string), endpoints (string[])
// Returns: {plaintext: base64, error?: string}
func decryptVTE(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return errorResponse("missing arguments: pkgJSON, endpoints")
	}

	pkgJSON := args[0].String()
	jsEndpoints := args[1]
	endpoints := make([]string, jsEndpoints.Length())
	for i := 0; i < jsEndpoints.Length(); i++ {
		endpoints[i] = jsEndpoints.Index(i).String()
	}

	var pkg vte.VTEPackageV2
	if err := json.Unmarshal([]byte(pkgJSON), &pkg); err != nil {
		return errorResponse(fmt.Sprintf("invalid package JSON: %v", err))
	}

	// Call real decryption
	ctx := context.Background()
	result, err := vte.DecryptVTE(ctx, &pkg, endpoints)
	if err != nil {
		return errorResponse(fmt.Sprintf("decryption failed: %v", err))
	}

	// Return plaintext as base64
	return map[string]interface{}{
		"plaintext": base64.StdEncoding.EncodeToString(result.R2),
	}
}
