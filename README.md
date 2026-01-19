# VoidSwap TLock (VTE-TLock) v0.2.1

**VoidSwap TLock** is a Verifiable Timelock Encryption (VTE) implementation designed for privacy-preserving, atomic swaps and time-released disclosures. It leverages Identity-Based Encryption (IBE) over the `drand` network and Zero-Knowledge Proofs (ZKP) to ensure that a ciphertext is bound to a specific network, round, and decryption identity before any funds are committed.

## 🚀 Overview

VTE-TLock solves the "trust" problem in timelock encryption. In standard timelock encryption, a receiver cannot verify if a ciphertext is actually decryptable at a future time without decrypting it. VTE-TLock adds a **Proof of Correct Encryption**, allowing anyone to verify:
1.  **Network Binding**: The ciphertext is for a specific `drand` chain and round.
2.  **Commitment Binding**: the secret $r_2$ used in the timelock is bound to a public commitment $C$.
3.  **Strict Structure**: The capsule follows the correct `age` / `tlock` format.

## 🏗️ Project Structure

-   `circuits/`: ZK circuits implemented in [Gnark](https://github.com/consensys/gnark).
    -   `secp/`: Proof of knowledge of a secret key for a secp256k1 public point $R_2$.
    -   `tle/`: Proof of correct IBE encryption (pairing-based) on BLS12-381.
-   `pkg/vte/`: Core Go library for protocol logic.
    -   `capsule.go`: Parser for `tlock` capsules and `age` headers.
    -   `verify.go`: Logic for strict network and structural verification.
    -   `types.go`: Shared protocol types and bindings.
-   `spec/`: Protocol specifications and test vectors.
-   `web/`: Next.js + MUI frontend demo.
    -   WASM-based client-side verification.
    -   Web Worker architecture for heavy crypto operations.

## 🛠️ Getting Started

### Prerequisites
-   Go 1.25+
-   Node.js 18+
-   Gnark dependencies (see [Gnark docs](https://docs.gnark.consensys.io/))

### Running the Frontend Demo

1.  **Build the WASM binary**:
    ```bash
    cd web/cmd/wasm
    $env:GOOS='js'; $env:GOARCH='wasm'; go build -o ../../public/vte_verifier.wasm .
    ```

2.  **Install Frontend Dependencies**:
    ```bash
    cd web
    npm install
    ```

3.  **Start the Dev Server**:
    ```bash
    npm run dev
    ```
    Access the UI at `http://localhost:3000`.

### Running Tests

To run the Go tests for the circuits and logic:
```bash
go test ./...
```

## 🔒 Security

VTE-TLock v0.2.1 enforces:
-   **Strict Network Binding**: Rejects capsules with mismatched `chainhash`.
-   **No Trust-Chain-Hash**: Forced verification of parameters to prevent relocation attacks.
-   **ZKP Verification**: Ensures mathematical proof of correct encryption before decryption is possible.

## 📜 Documentation

For detailed protocol semantics, see:
-   [VTE Specification](spec/vte-spec.md) (Draft)
-   [Test Vectors](spec/testvectors.md)

---
Developed as part of the VoidSwap privacy-preserving atomic swap protocol.
