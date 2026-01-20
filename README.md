# VTE-TLock v0.2.0 (Schema vte-tlock/0.2)

**Verifiable Time-Locked Encryption** using drand and Zero-Knowledge Proofs

A cryptographic system for time-locked encryption with verifiable computation. Encrypt secrets that can only be revealed after a specific future time, backed by the drand randomness beacon network.

---

## 🎯 What is VTE-TLock?

VTE-TLock enables **trustless time-locked encryption**:
- 🔒 **Encrypt** a secret so it cannot be decrypted until a future time
- ⏰ **Calendar picker** - select unlock date/time with minute-level precision  
- ✅ **Verifiable** with cryptographic commitments and ZK proofs (Schema V2)
- 🌐 **Browser-based** with Go WASM backend (no server required)
- 🛡️ **Trustless Verification**: Policy-driven checks ensuring package integrity without trusting package metadata.

### Use Cases
- **Atomic Swaps**: Lock refund transactions until swap completes
- **Sealed-Bid Auctions**: Encrypt bids until auction closes  
- **Dead Man's Switch**: Auto-reveal secrets after inactivity
- **Scheduled Disclosures**: Time-locked announcements

---

## 🚀 Quick Start

### Prerequisites
- **Go** 1.21+ ([install](https://go.dev/dl/))
- **Node.js** 18+ ([install](https://nodejs.org/))

### Installation

```bash
# 1. Clone repository
git clone https://github.com/inspirezuza/vte-tlock.git
cd vte-tlock

# 2. Install dependencies
go mod download
cd web && npm install

# 3. Build WASM binary (V2)
cd cmd/wasm
# Windows PowerShell:
$env:GOOS='js'; $env:GOARCH='wasm'; go build -o ../../public/wasm/vte_tlock_v2.wasm .
# Linux/Mac:
# GOOS=js GOARCH=wasm go build -o ../../public/wasm/vte_tlock_v2.wasm .

# 4. Start dev server
cd ../..
npm run dev
```

Open browser: **http://localhost:3000**

---

## 📖 How to Use

### 1. Generate VTE Package
1. **Navigate to** http://localhost:3000/generate
2. **Step 1 - Context Mapping**: Enter session ID and refund TX (hex)
3. **Step 2 - Network Configuration**: Select unlock time (auto-computes round)
4. **Step 3 - Secret**: Enter plaintext message or generate random r2
5. **Step 4 - Generate**: Click "Generate & Prove" → get `vte-tlock/0.2` JSON package

### 2. Verify VTE Package
1. **Navigate to** http://localhost:3000/verify
2. **Paste** your VTE package JSON
3. **Configure Policy**: Verify against expected Chain Hash, Round, Session ID, and Refund TX.
4. **Click** "Verify & Audit Package"
   - ✅ **Structural Integrity**: Validates V2 schema
   - ✅ **Policy Check**: Ensures packet matches your expected context
   - ✅ **Cryptographic Binding**: Verifies ZK proofs bind ciphertext to context

### 3. Decrypt VTE Package
1. **Navigate to** http://localhost:3000/decrypt
2. **Paste** your VTE package JSON
3. **Provide Endpoints**: Enter trusted Drand API endpoints (e.g. `https://api.drand.sh`) - *Security Feature: Endpoints are not trusted from package*
4. **Wait** for unlock time
5. **Click** "Fetch Beacon & Decrypt" after unlock

---

## ✅ Features Working

| Feature | Status | Notes |
|---------|--------|-------|
| **VTE Schema V2** | ✅ | Self-contained, deterministic context binding |
| **Trustless Verification** | ✅ | Verifier provides policy/context facts |
| **TLock Encryption** | ✅ | Real IBE encryption via drand |
| **TLock Decryption** | ✅ | Requires external endpoints for security |
| **ZK Proof Generation** | ✅ | Groth16 MiMC commitment proof |
| **ZK Proof Verification** | ✅ | Verify before unlock time |
| **WASM Worker** | ✅ | Non-blocking cryptographic operations |

---

## 🔧 Project Structure

```
vte-tlock/
├── circuits/                    # ZK circuits
│   ├── commitment/             # ✅ MiMC commitment
│   └── secp/                   # SECP256k1 circuit
│
├── pkg/vte/                    # Go backend core
│   ├── package.go              # VTE V2 generation
│   ├── types.go                # V2 Schema Definitions
│   ├── verify.go               # Trustless verification logic
│   └── tlock.go                # TLock encryption
│
├── web/                        # Next.js frontend
│   ├── workers/vte.worker.ts   # WASM worker (handles V2 args)
│   ├── lib/vte/client.ts       # TypeScript WASM client
│   └── cmd/wasm/main.go        # V2 WASM bindings
```

---

## 🔬 Technical Details (Schema V2)

### Context Binding
The verification context is cryptographically bound to the proofs using a holistic hash:
```go
CtxHash = SHA256(
    "VTE_CTX_V2" || 
    ChainHash || 
    Round || 
    CapsuleHash || 
    SessionID || 
    RefundTx
)
```
This ensures that the proofs are valid ONLY for the specific ciphertext and context parameters.

### Trust Architecture
- **Generation**: Produces a self-contained package with all necessary proofs.
- **Verification**: Does NOT trust the package for critical parameters (Round, Chain). The Verifier MUST supply these "expected" values.
- **Decryption**: Does NOT use endpoints from the package (preventing malicious redirections). The user MUST supply trusted Drand endpoints.

---

## 📄 License

MIT License

---

## 🔗 Resources

- **drand**: https://drand.love
- **tlock**: https://github.com/drand/tlock
- **gnark**: https://github.com/ConsenSys/gnark

---

Developed as part of the VoidSwap privacy-preserving atomic swap protocol.
