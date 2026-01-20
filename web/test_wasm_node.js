const fs = require('fs');
const crypto = require('crypto');

// Polyfill global fetch/TextEncoder for Go WASM environment if needed (Go's wasm_exec handles most)
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
    
    console.log("WASM Loaded. Testing generateVTE...");
    
    // Mock Arguments
    const round = 1000;
    const chainHash = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"; // Quicknet
    const formatId = "tlock_v1_age_pairing";
    const r2 = "00".repeat(32); // 32 bytes
    const refundTx = "1234";
    const sessionId = "test-session";
    // JS arrays passed as objects with Length/Index methods in browser, 
    // BUT in Node `syscall/js`, we might need to mock the JS interaction differently 
    // or rely on go's `js.Value`. 
    // Native node arrays are wrapped automatically by syscall/js.
    
    // However, main.go expects JS objects with Length() and Index(). 
    // Standard arrays in Node passed to Go via syscall/js usually work as transparent JS values, 
    // but the Go code `jsEndpoints.Length()` calls might fail if it's not a Go-wrapper-friendly object.
    // Actually, `syscall/js` maps JS arrays to a value where .Length() is a property lookup, not a method?
    // In main.go: `endpoints := make([]string, jsEndpoints.Length())`. 
    // Go's `Length()` method on `js.Value` calls the `length` property.
    // `Index(i)` calls `Get(string(i))`.
    // So a standard JS array works!
    
    const endpoints = ["https://api.drand.sh"];
    const strategy = "auto";
    const storedEndpoints = [];
    
    // Chain Info JSON (Mock)
    const chainInfo = JSON.stringify({
        public_key: "a1b2c3d4", // Needs to be hex? No, tlock parses it. 
        // Wait, tlock expects public_key to be hex.
        // Let's use a real-ish public key or TLock will fail parsing.
        // Quicknet public key:
        public_key: "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a089c8313083bebc8527e05",
        period: 3,
        genesis_time: 1692803367,
        hash: chainHash,
        groupHash: "1234",
        schemeID: "pedersen-bls-chained",
        metadata: { "beaconID": "quicknet" }
    });
    
    const beaconSig = ""; // Empty - testing future round!
    
    try {
        const resRaw = global.generateVTE(
            round,
            chainHash,
            formatId,
            r2,
            refundTx,
            sessionId,
            endpoints,
            strategy,
            storedEndpoints,
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
        console.log("Round:", res.round);
        console.log("Capsule length:", res.capsule.length);
        console.log("Proof Secp:", res.proof_secp ? "Present" : "Missing");
        
    } catch (e) {
        console.error("❌ Execution Error:", e);
        process.exit(1);
    }
}

runTest();
