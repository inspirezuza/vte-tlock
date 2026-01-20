# VTE-TLock v0.3.0

**Verifiable Time-Locked Encryption** using drand and Zero-Knowledge Proofs

A cryptographic system for time-locked encryption with verifiable computation. Encrypt secrets that can only be revealed after a specific future time, backed by the drand randomness beacon network.

---

## 🎯 What is VTE-TLock?

VTE-TLock enables **trustless time-locked encryption**:
- 🔒 **Encrypt** a secret so it cannot be decrypted until a future time
- ⏰ **Calendar picker** - select unlock date/time with minute-level precision  
- ✅ **Verifiable** with cryptographic commitments and ZK proofs
- 🌐 **Browser-based** with Go WASM backend (no server required)

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
git clone https://github.com/yourusername/vte-tlock.git
cd vte-tlock

# 2. Install dependencies
go mod download
cd web && npm install

# 3. Build WASM binary
cd cmd/wasm
# Windows PowerShell:
$env:GOOS='js'; $env:GOARCH='wasm'; go build -o ../../public/wasm/vte_tlock.wasm .
# Linux/Mac:
# GOOS=js GOARCH=wasm go build -o ../../public/wasm/vte_tlock.wasm .

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
3. **Step 2 - Network Configuration**:
   - 📅 **Select unlock time** using calendar picker (1-60 minute precision)
   - System auto-computes target drand round
   - *Advanced mode*: Manual round entry for devs/auditors
4. **Step 3 - Secret**: Enter plaintext message or generate random r2
5. **Step 4 - Generate**: Click "Generate & Prove" → get JSON package

### 2. Verify VTE Package

1. **Navigate to** http://localhost:3000/verify
2. **Paste** your VTE package JSON
3. **Click** "Verify & Audit Package"
4. **Review** audit results:
   - ✅ Structural integrity
   - ✅ Network binding (chain hash, round)
   - ✅ Capsule binding (R2 point, commitment)
   - ✅ ZK Proof verification

### 3. Decrypt VTE Package

1. **Navigate to** http://localhost:3000/decrypt
2. **Paste** your VTE package JSON
3. **Wait** for unlock time (countdown shown)
4. **Click** "Fetch Beacon & Decrypt" after unlock
5. **View** decrypted plaintext

---

## ✅ Features Working

| Feature | Status | Notes |
|---------|--------|-------|
| **Calendar DateTime Picker** | ✅ | Select unlock time with 1-minute precision |
| **Auto Round Computation** | ✅ | Computed from drand chain params |
| **TLock Encryption** | ✅ | Real IBE encryption via drand |
| **TLock Decryption** | ✅ | Fetches beacon post-unlock |
| **ZK Proof Generation** | ✅ | Groth16 MiMC commitment proof |
| **ZK Proof Verification** | ✅ | Verify before unlock time |
| **Plaintext Mode** | ✅ | SHA256(plaintext) → r2 |
| **secp256k1 Points** | ✅ | Real ECC: R2 = r2 × G |
| **MiMC Commitments** | ✅ | ZK-friendly hash |

---

## 🔧 Project Structure

```
vte-tlock/
├── circuits/                    # ZK circuits
│   ├── commitment/             # ✅ MiMC commitment (661 constraints)
│   └── secp/                   # SECP256k1 circuit
│
├── pkg/vte/                    # Go backend core
│   ├── package.go              # VTE generation + ZK proof
│   ├── crypto.go               # secp256k1, commitments
│   ├── tlock.go                # TLock encryption (native)
│   ├── tlock_wasm.go           # TLock with JS pre-fetch
│   ├── decrypt.go              # TLock decryption
│   └── verify.go               # Package verification
│
├── web/                        # Next.js frontend
│   ├── app/                    # Pages (dashboard, generate, verify, decrypt)
│   ├── components/             # React components (Generator, Verifier, etc.)
│   ├── workers/vte.worker.ts   # WASM worker + drand pre-fetch
│   ├── lib/vte/client.ts       # TypeScript WASM client
│   └── cmd/wasm/main.go        # WASM bindings
```

---

## 🔬 Technical Details

### Drand Network (Quicknet)
- **Chain Hash**: `52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971`
- **Period**: 3 seconds per round
- **Endpoint**: https://api.drand.sh

### Round Calculation
```
target_round = ceil((unlock_timestamp - genesis_time) / period)
```

### WASM Architecture
The WASM module uses JavaScript pre-fetching for all network requests to avoid blocking:
1. Worker fetches chain info & beacon via `fetch()` API
2. Passes JSON to WASM as string parameters
3. WASM processes locally without network calls

---

## 🐛 Troubleshooting

### "Failed to fetch chain params"
- Check internet connection
- Verify drand endpoint is reachable
- Try alternative: https://drand.cloudflare.com

### "Verification failed"
- Ensure package was generated with current version
- Check chain hash matches network

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
