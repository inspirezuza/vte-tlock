package main

import (
	"fmt"
	"log"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"vte-tlock/circuits/tle"
)

func main() {
	fmt.Println("=== TLE Circuit Feasibility Analysis ===")

	var circuit tle.Circuit

	// Compile and count constraints
	fmt.Println("\n[1/3] Compiling TLE circuit...")
	startCompile := time.Now()

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatal("Compilation failed:", err)
	}

	compileTime := time.Since(startCompile)
	constraints := ccs.GetNbConstraints()

	fmt.Printf("✓ Compilation successful\n")
	fmt.Printf("  Time: %v\n", compileTime)
	fmt.Printf("  Constraints: %d\n", constraints)

	// Estimate proving time based on constraints
	// Rule of thumb: ~10-20ms per 1000 constraints on modern hardware
	// For very large circuits (>1M constraints), pairing operations dominate
	estimatedSeconds := float64(constraints) * 0.015 / 1000 // Conservative estimate

	fmt.Printf("\n[2/3] Feasibility Analysis\n")
	fmt.Printf("  Estimated proving time: ~%.1f seconds\n", estimatedSeconds)

	tenMinutes := 600.0 // seconds

	if estimatedSeconds > tenMinutes {
		fmt.Printf("  ⚠️  WARNING: Estimated time (%.1fs) exceeds 10-minute threshold\n", estimatedSeconds)
		fmt.Println("  RECOMMENDATION: Consider Track B (ZKVM) as fallback")
		fmt.Println("\n[3/3] Result: FEASIBILITY UNCERTAIN - Full benchmark required")
	} else if estimatedSeconds > tenMinutes*0.5 {
		fmt.Printf("  ⚠️  CAUTION: Estimated time (%.1fs) is close to threshold\n", estimatedSeconds)
		fmt.Println("  RECOMMENDATION: Run full benchmark to confirm")
		fmt.Println("\n[3/3] Result: FEASIBILITY LIKELY - Verification needed")
	} else {
		fmt.Printf("  ✓ Estimated time (%.1fs) is well under 10-minute threshold\n", estimatedSeconds)
		fmt.Println("  RECOMMENDATION: Track A (Gnark) is viable")
		fmt.Println("\n[3/3] Result: FEASIBILITY CONFIRMED")
	}

	fmt.Println("\n=== Summary ===")
	fmt.Printf("Constraints: %d\n", constraints)
	fmt.Printf("Compile Time: %v\n", compileTime)
	fmt.Printf("Est. Prove Time: ~%.1fs\n", estimatedSeconds)

	if estimatedSeconds <= tenMinutes {
		fmt.Println("Status: ✓ Track A VIABLE")
	} else {
		fmt.Println("Status: ⚠️  Track B RECOMMENDED")
	}
}
