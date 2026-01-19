
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
                const response = await fetch(`${origin}/wasm/vte_tlock.wasm`);
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
                // @ts-ignore
                const res = self.generateVTE(
                    payload.round,
                    payload.chainHash,
                    payload.formatId,
                    payload.r2,
                    payload.ctxHash,
                    payload.endpoints,
                    payload.strategy || 'auto'
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
                const hash = self.computeCtxHash(payload.sessionId, payload.refundTx);
                self.postMessage({ id, type: 'OK', payload: hash });
                break;
            }

            case 'DECRYPT_VTE': {
                if (!wasmReady) throw new Error("WASM not initialized");
                // @ts-ignore
                const result = self.decryptVTE(payload.packageJSON);
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
                    payload.ctxHash
                );
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
