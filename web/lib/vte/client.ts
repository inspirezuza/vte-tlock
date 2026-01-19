
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

    private send(type: string, payload: any): Promise<any> {
        if (!this.worker) return Promise.reject(new Error("Worker not available"));
        
        const id = (this.idCounter++).toString();
        return new Promise((resolve, reject) => {
            this.handlers.set(id, { resolve, reject });
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
        ctxHash: string;
        endpoints: string[];
        strategy: 'gnark' | 'zkvm' | 'auto';
    }) {
        return this.send('GENERATE_VTE', params);
    }

    async computeCtxHash(sessionId: string, refundTx: string) {
        return this.send('COMPUTE_CTX_HASH', { sessionId, refundTx });
    }

    async decrypt(packageJSON: string) {
        return this.send('DECRYPT_VTE', { packageJSON });
    }

    async verifyVTE(params: {
        jsonInput: string;
        round: number;
        chainHash: string;
        formatId: string;
        ctxHash: string;
    }) {
        return this.send('VERIFY_VTE', params);
    }

    async parseCapsule(capsule: string, formatId: string) {
        return this.send('PARSE_CAPSULE', { capsule, formatId });
    }
}

// Export a singleton instance
export const vteClient = new VTEClient();
export default vteClient;
