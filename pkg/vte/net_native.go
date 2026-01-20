//go:build !js || !wasm
// +build !js !wasm

package vte

import (
	"github.com/drand/tlock"
	tlockHttp "github.com/drand/tlock/networks/http"
)

func NewNetwork(endpoint, chainHash string) (tlock.Network, error) {
	return tlockHttp.NewNetwork(endpoint, chainHash)
}
