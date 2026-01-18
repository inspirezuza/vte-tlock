package tle

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

func TestCircuitCompilation(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit Circuit
	// We check if Compile works (valid constraints generation)
	_, errCompile := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(errCompile, "Circuit should compile")
}
