const fs = require('fs');
const crypto = require('crypto');

// Polyfill global fetch/TextEncoder for Go WASM environment
if (!global.TextEncoder) {
    const { TextEncoder, TextDecoder } = require('util');
    global.TextEncoder = TextEncoder;
    global.TextDecoder = TextDecoder;
}

// Load wasm_exec.js
require('./public/wasm/wasm_exec.js');

async function runTest() {
    const go = new Go();
    
    // Read WASM file
    const wasmBuffer = fs.readFileSync('./public/wasm/vte_tlock_v2.wasm');
    
    // Instantiate
    const result = await WebAssembly.instantiate(wasmBuffer, go.importObject);
    go.run(result.instance);
    
    console.log("WASM Loaded. Testing generateVTE with V2 args (10 args)...");
    
    // Mock Arguments (matching vte.worker.ts V2 call)
    const round = 1000;
    const chainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"; // Quicknet
    const formatId = "tlock_v1_age_pairing";
    const r2 = "00".repeat(32); // 32 bytes
    const refundTx = "1234"; // hex
    const sessionId = "test-session";
    const endpoints = ["https://api.drand.sh"];
    const strategy = "auto";
    // canonicalEndpoints REMOVED in V2 worker call
    
    // Chain Info JSON (Mock)
    const chainInfo = JSON.stringify({
        public_key: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a089c8313083bebc8527e05",
        period: 3,
        genesis_time: 1692803367,
        hash: chainHash,
        groupHash: "1234",
        schemeID: "bls-unchained-on-g1",
        metadata: { "beaconID": "quicknet" }
    });
    
    const beaconSig = ""; // Empty
    
    try {
        // Call with 10 arguments (Index 0-9)
        // main.go currently expects ChainInfo at Index 9? Or 8?
        // Worker passes: round(0), chainHash(1), formatId(2), r2(3), refundTx(4), sessionId(5), endpoints(6), strategy(7), chainInfo(8), beacon(9)
        const resRaw = global.generateVTE(
            round,
            chainHash,
            formatId,
            r2,
            refundTx,
            sessionId,
            endpoints,
            strategy,
            chainInfo,
            beaconSig
        );

        if (typeof resRaw === 'object') {
            console.error("❌ generateVTE returned Error Object:", resRaw);
            process.exit(1);
        }

        const res = JSON.parse(resRaw);
        if (res.error) {
            console.error("❌ Test Failed with VTE Error:", res.error);
            process.exit(1);
        }
        
        console.log("✅ VTE Generated Successfully!");
        console.log("Version:", res.version);
        
    } catch (e) {
        console.error("❌ Execution Error:", e);
        process.exit(1);
    }
}

runTest();
