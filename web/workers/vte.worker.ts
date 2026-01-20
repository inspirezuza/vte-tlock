
// vte.worker.ts
// Handles WASM loading and VTE operations off the main thread.

/* eslint-disable no-restricted-globals */

try {
    const origin = self.location.origin;
    // @ts-ignore
    self.importScripts(`${origin}/wasm/wasm_exec.js`);
} catch (e) {
    console.error("[Worker] Failed to import wasm_exec.js:", e);
}

let wasmReady = false;
let go: any = null;

self.onmessage = async (e: MessageEvent) => {
    const { id, type, payload } = e.data;

    try {
        switch (type) {
            case 'INIT': {
                if (wasmReady) {
                    self.postMessage({ id, type: 'OK', payload: { status: 'Already Initialized' } });
                    return;
                }
                
                // @ts-ignore
                go = new self.Go();
                const origin = self.location.origin;
                // Load v2 WASM to bypass file locks and cache
                const response = await fetch(`${origin}/wasm/vte_tlock_v2.wasm?v=${Date.now()}`);
                if (!response.ok) throw new Error(`Fetch failed: ${response.status} ${response.statusText}`);
                
                const buffer = await response.arrayBuffer();
                const result = await WebAssembly.instantiate(buffer, go.importObject);
                
                // Go runtime run blocks, so we don't await it
                go.run(result.instance);

                let retries = 0;
                // @ts-ignore
                while (!self.verifyVTE && retries < 50) {
                    await new Promise(r => setTimeout(r, 100));
                    retries++;
                }

                // @ts-ignore
                if (self.verifyVTE) {
                    wasmReady = true;
                    self.postMessage({ id, type: 'OK', payload: { status: 'WASM Runtime Ready' } });
                } else {
                    throw new Error("WASM initialization timed out");
                }
                break;
            }
            case 'GENERATE_VTE': {
                if (!wasmReady) throw new Error("WASM not initialized");
                
                // Pre-fetch chain info from drand API (in JS to avoid WASM deadlock)
                // NOTE: For ENCRYPTION, we only need chain info (public key), NOT the beacon!
                const endpoint = payload.endpoints[0] || 'https://api.drand.sh';
                const chainHash = payload.chainHash;
                
                // Fetch chain info only
                const infoUrl = `${endpoint}/${chainHash}/info`;
                const infoResp = await fetch(infoUrl);
                if (!infoResp.ok) {
                    throw new Error(`Failed to fetch chain info: ${infoResp.status}`);
                }
                const chainInfoJSON = await infoResp.text();
                
                // No beacon needed for encryption - it's for future rounds!
                const beaconSignatureHex = ''; 
                
                // @ts-ignore
                const res = self.generateVTE(
                    payload.round,
                    payload.chainHash,
                    payload.formatId,
                    payload.r2,
                    payload.refundTxHex, 
                    payload.sessionId,
                    payload.endpoints,
                    payload.strategy || 'auto',
                    // payload.canonicalEndpoints || [], // Removed in V2
                    chainInfoJSON,
                    beaconSignatureHex
                );
                if (typeof res === 'string') {
                    self.postMessage({ id, type: 'OK', payload: JSON.parse(res) });
                } else {
                    self.postMessage({ id, type: 'OK', payload: res });
                }
                break;
            }
            case 'COMPUTE_CTX_HASH': {
                if (!wasmReady) throw new Error("WASM not initialized");
                // @ts-ignore
                // V2 requires full context params: sessionID, refundTxHex, chainHashHex, round, capsuleHashHex
                const hash = self.computeCtxHash(
                    payload.sessionId, 
                    payload.refundTx,
                    payload.chainHash,
                    payload.round,
                    payload.capsuleHash
                );
                self.postMessage({ id, type: 'OK', payload: hash });
                break;
            }

            case 'DECRYPT_VTE': {
                if (!wasmReady) throw new Error("WASM not initialized");
                // @ts-ignore
                // V2 requires endpoints provided by caller
                const result = self.decryptVTE(payload.packageJSON, payload.endpoints);
                if (result.error) {
                    self.postMessage({ id, type: 'ERR', error: result.error });
                } else {
                    self.postMessage({ id, type: 'OK', payload: result });
                }
                break;
            }
            case 'VERIFY_VTE': {
                if (!wasmReady) throw new Error("WASM not initialized");
                // @ts-ignore
                const res = self.verifyVTE(
                    payload.jsonInput,
                    payload.round,
                    payload.chainHash,
                    payload.formatId,
                    payload.sessionId, // Binding check
                    payload.refundTxHex
                );
                self.postMessage({ id, type: 'OK', payload: res });
                break;
            }
            case 'COMPUTE_R2_POINT': {
                if (!wasmReady) throw new Error("WASM not initialized");
                // @ts-ignore
                const res = self.computeR2Point(payload.r2Hex);
                self.postMessage({ id, type: 'OK', payload: res });
                break;
            }
            case 'PARSE_CAPSULE': {
                if (!wasmReady) throw new Error("WASM not initialized");
                // @ts-ignore
                const res = self.parseCapsule(payload.capsule, payload.formatId);
                self.postMessage({ id, type: 'OK', payload: res });
                break;
            }
            default:
                throw new Error(`Unknown message type: ${type}`);
        }
    } catch (err: any) {
        self.postMessage({ id, type: 'ERR', payload: { message: err.message } });
    }
};
