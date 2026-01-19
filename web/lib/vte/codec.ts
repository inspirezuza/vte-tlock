
// Hex <-> Bytes
export function hexToBytes(hex: string): Uint8Array {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
        bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Base64 <-> Bytes (Browser safe)
export function base64ToBytes(base64: string): Uint8Array {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Helper to view Base64 as Hex (for debugging)
export const base64ToHex = (b64: string): string => {
    try {
        const bin = atob(b64);
        let hex = '';
        for (let i = 0; i < bin.length; i++) {
            const h = bin.charCodeAt(i).toString(16);
            hex += h.length === 1 ? '0' + h : h;
        }
        return hex;
    } catch (e) {
        return '';
    }
};

export const hexToBase64 = (hex: string): string => {
    try {
        if (hex.length % 2 !== 0) return '';
        const bytes = new Uint8Array(hex.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
        let bin = '';
        bytes.forEach(b => bin += String.fromCharCode(b));
        return btoa(bin);
    } catch (e) {
        return '';
    }
};

export const codec = {
    hexToBytes,
    bytesToHex,
    base64ToBytes,
    bytesToBase64,
    base64ToHex,
    hexToBase64
};
