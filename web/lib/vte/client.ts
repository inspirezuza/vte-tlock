
import { WorkerResponse } from './types';

class VTEClient {
    private worker: Worker | null = null;
    private idCounter = 0;
    private handlers = new Map<string, { resolve: (val: any) => void; reject: (err: any) => void }>();
    private initialized = false;

    constructor() {
        if (typeof window !== 'undefined') {
            this.worker = new Worker(new URL('../../workers/vte.worker.ts', import.meta.url));
            this.worker.onmessage = this.handleMessage.bind(this);
        }
    }

    private handleMessage(e: MessageEvent<WorkerResponse>) {
        const { id, type, payload } = e.data;
        const handler = this.handlers.get(id);
        if (!handler) return;

        if (type === 'OK') {
            handler.resolve(payload);
        } else if (type === 'ERR') {
            handler.reject(new Error(payload.message || 'Worker error'));
        }
        this.handlers.delete(id);
    }

    private send(type: string, payload: any, timeoutMs: number = 60000): Promise<any> {
        if (!this.worker) return Promise.reject(new Error("Worker not available"));
        
        const id = (this.idCounter++).toString();
        return new Promise((resolve, reject) => {
            // Set up timeout
            const timeout = setTimeout(() => {
                this.handlers.delete(id);
                reject(new Error(`Worker request timeout after ${timeoutMs/1000}s for ${type}`));
            }, timeoutMs);
            
            this.handlers.set(id, { 
                resolve: (val) => {
                    clearTimeout(timeout);
                    resolve(val);
                },
                reject: (err) => {
                    clearTimeout(timeout);
                    reject(err);
                }
            });
            this.worker!.postMessage({ id, type, payload });
        });
    }

    async init() {
        if (this.initialized) return;
        await this.send('INIT', {});
        this.initialized = true;
    }

    async generateVTE(params: {
        round: number;
        chainHash: string;
        formatId: string;
        r2: string;
        refundTxHex: string;
        sessionId: string;
        endpoints: string[];
        // canonicalEndpoints removed in V2
        strategy: 'gnark' | 'zkvm' | 'auto';
    }) {
        return this.send('GENERATE_VTE', params);
    }

    async computeCtxHash(sessionId: string, refundTx: string, chainHash: string, round: number, capsuleHash: string) {
        return this.send('COMPUTE_CTX_HASH', { sessionId, refundTx, chainHash, round, capsuleHash });
    }

    async decrypt(packageJSON: string, endpoints: string[]) {
        return this.send('DECRYPT_VTE', { packageJSON, endpoints });
    }

    async verifyVTE(params: {
        jsonInput: string;
        round: number;
        chainHash: string;
        formatId: string;
        sessionId: string;
        refundTxHex: string;
    }) {
        return this.send('VERIFY_VTE', params);
    }

    async parseCapsule(capsule: string, formatId: string) {
        return this.send('PARSE_CAPSULE', { capsule, formatId });
    }

    async computeR2Point(r2Hex: string): Promise<{ R2?: string; error?: string }> {
        return this.send('COMPUTE_R2_POINT', { r2Hex });
    }
}

// Export a singleton instance
export const vteClient = new VTEClient();
export default vteClient;
