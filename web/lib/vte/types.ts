
export interface NetworkID {
    chain_hash: string;           // Base64
    tlock_version: string;
    ciphertext_format_id: string;
    trust_chain_hash: boolean;
    drand_endpoints: string[];
}

export interface CipherFields {
    ephemeral_pub_key: string;    // Base64
    mask: string;                 // Base64
    tag: string;                  // Base64
    ciphertext: string;           // Base64
}

export interface R2PublicInputs {
    r2x: string[][];              // Base64 of 16-byte limbs [2][16]? No, Go is [2][16]byte. 
                                  // JSON marshals [2][16]byte as array of 2 Base64 strings? 
                                  // Actually Go's json.Marshal of [N]byte is Base64 string.
                                  // [2][16]byte -> [ "Base64(16bytes)", "Base64(16bytes)" ]
    r2y: string[][];
}

export interface VTEPackage {
    round: number;
    network_id: NetworkID;
    capsule: string;              // Base64
    capsule_checksum: string;     // Base64
    cipher_fields: CipherFields;
    ctx_hash: string;             // Base64
    c: string;                    // Base64
    r2_compressed: string;        // Base64
    r2_pub: R2PublicInputs;
    proof_secp: string;           // Base64
    proof_tle: string;            // Base64
}

// Worker Protocol Types
export type WorkerRequestType = 'INIT' | 'GEN_SECP' | 'GEN_TLE' | 'VERIFY_VTE' | 'DECRYPT';

export interface WorkerRequest {
    id: string;
    type: WorkerRequestType;
    payload: any;
}

export interface WorkerResponse {
    id: string;
    type: 'OK' | 'ERR' | 'PROGRESS';
    payload: any;
}
