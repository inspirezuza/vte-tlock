'use client';

import { useState, useEffect } from 'react';
import {
    Button,
    Card,
    CardContent,
    Typography,
    TextField,
    Alert,
    CircularProgress,
    Stack,
    Chip
} from '@mui/material';
import LockIcon from '@mui/icons-material/Lock';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';

// Initialize WASM
const loadWasm = async () => {
    // @ts-ignore
    const go = new Go();
    const result = await WebAssembly.instantiateStreaming(
        fetch('/vte_verifier.wasm'),
        go.importObject
    );
    go.run(result.instance);
};

export default function Verifier() {
    const [isWasmLoaded, setIsWasmLoaded] = useState(false);
    const [jsonInput, setJsonInput] = useState('');
    const [chainHash, setChainHash] = useState('');
    const [round, setRound] = useState('');
    const [result, setResult] = useState<any>(null);
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        loadWasm().then(() => setIsWasmLoaded(true)).catch(console.error);
    }, []);

    if (!mounted) return null;

    const loadSample = () => {
        // Construct a dummy age capsule
        // Stanza body: 32 bytes of 0x01.
        // Base64Raw: AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE
        const stanzaBody = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
        const mask = "AQEBAQEBAQEBAQEBAQEBAQ=="; // 16 bytes of 0x01
        const tag = "AQEBAQEBAQEBAQEBAQEBAQ==";  // 16 bytes of 0x01
        // Payload: "DATA" -> "REFUQQ=="
        
        const chainHash = "8990e7a9aaed2f2b79c43d7890f5a77042845c088af85050f28a25c13e53625f";
        const round = 1000;
        
        const ageHeader = `age-encryption.org/v1
-> tlock ${round} ${chainHash}
${stanzaBody}
--- token
DATA`;

        // Encode capsule to base64
        const capsuleB64 = btoa(ageHeader);

        setJsonInput(JSON.stringify({
            "round": round,
            "network_id": {
                "chain_hash": chainHash, // Base64 needed? No, struct says []byte. JSON marshals []byte as B64. 
                // Wait, NetworkID struct has ChainHash []byte. So JSON expects Base64.
                // But my verifyVTE wrapper (main.go) expects pkg JSON.
                // Go's json.Unmarshal decodes strings to []byte for []byte fields.
                // So I need Base64 of the hex chain hash.
                // chainHash string above is HEX.
                // I need to convert Hex to Bytes to Base64.
                // Since this is JS, I'll just hardcode the Base64 of that hex.
                // Hex: 8990...
                // I'll calculate it or just put a simpler one.
                // Actually, let's use a dummy chainhash that matches the input.
                // 16 bytes: "00...00" -> "AAAA...AAAA=="
            },
            // Update: NetworkID struct in types.go:
            // ChainHash []byte.
            // But verifyVTE wrapper takes chainHash as HEX string argument (args[2]).
            // AND it unmarshals `pkg` from args[0].
            // `pkg.NetworkID.ChainHash` is compared against `expectedChainHash`.
            
            "capsule": capsuleB64,
            "cipher_fields": {
                "ephemeral_pub_key": null, // or empty string
                "mask": mask,
                "tag": tag,
                "ciphertext": "REFUQQ==" // Base64 of "DATA"
            },
            // We need to match NetworkID.ChainHash in the package with the one passed as arg.
            // main.go: check pkg.NetworkID.Validate(expectedChainHash...)
            // So I need to set pkg.NetworkID.ChainHash to match the `chainHash` state variable.
            // The `chainHash` state variable is passed as Hex string to Go.
            // Go converts Hex to Bytes.
            // `pkg` JSON must have Base64 of those bytes.
            // I'll use a simple chainhash: 32 bytes of 0x01.
            // Hex: 0101...
            // Base64: AQE...
        }, null, 2));
        
        // Let's use simplified consistent data.
        setRound("1000");
        const dummyChainHashHex = "0101010101010101010101010101010101010101010101010101010101010101";
        setChainHash(dummyChainHashHex);
        
        // Re-construct with consistent data
        const capsuleB64Updated = btoa(`age-encryption.org/v1
-> tlock 1000 ${dummyChainHashHex}
${stanzaBody}
--- token
DATA`);

        setJsonInput(JSON.stringify({
            "round": 1000,
            "network_id": {
                "chain_hash": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", // Base64 of 32 bytes 0x01
                "tlock_version": "v1.0.0",
                "ciphertext_format_id": "tlock_v1_age_pairing",
                "trust_chain_hash": false,
                "drand_endpoints": []
            },
            "capsule": capsuleB64Updated,
            "capsule_checksum": null, 
            "cipher_fields": {
                "ephemeral_pub_key": null, 
                "mask": mask,
                "tag": tag,
                "ciphertext": "REFUQQ==" 
            },
            "ctx_hash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 bytes zeros
            "c": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "r2_compressed": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // 33 bytes
            "r2_pub": { "r2x": null, "r2y": null }, // Optional if not validated yet
            "proof_secp": null,
            "proof_tle": null
        }, null, 2));
    };

    const handleVerify = () => {
        setLoading(true);
        setError('');
        setResult(null);

        setTimeout(() => {
            try {
                // @ts-ignore
                if (!window.verifyVTE) {
                    throw new Error("WASM not loaded");
                }

                // Default context/format for "demo" (would be inputs in real app)
                const formatId = "tlock_v1_age_pairing"; 
                // Dummy ctx hash for demo if not provided
                const ctxHash = "0000000000000000000000000000000000000000000000000000000000000000";

                // @ts-ignore
                const res = window.verifyVTE(
                    jsonInput,
                    parseInt(round),
                    chainHash,
                    formatId,
                    ctxHash
                );

                if (res.error) {
                    setError(res.error);
                } else {
                    setResult(res);
                }
            } catch (e: any) {
                setError(e.message);
            } finally {
                setLoading(false);
            }
        }, 100);
    };

    return (
        <Card sx={{ minWidth: 275, maxWidth: 800, mx: 'auto', mt: 4 }}>
            <CardContent>
                <Stack direction="row" alignItems="center" spacing={1} mb={2} justifyContent="space-between">
                    <Stack direction="row" alignItems="center" spacing={1}>
                        <VerifiedUserIcon color="primary" fontSize="large" />
                        <Typography variant="h5" component="div">
                            VTE Verifier
                        </Typography>
                        {isWasmLoaded ? 
                            <Chip label="WASM Active" color="success" size="small" /> : 
                            <Chip label="Loading WASM..." color="warning" size="small" />
                        }
                    </Stack>
                    <Button size="small" variant="outlined" onClick={loadSample}>
                        Load Sample
                    </Button>
                </Stack>
                  
                <TextField
                    label="VTE Package JSON"
                    multiline
                    rows={6}
                    fullWidth
                    variant="outlined"
                    value={jsonInput}
                    onChange={(e) => setJsonInput(e.target.value)}
                    sx={{ mb: 2 }}
                />
                
                <Stack direction="row" spacing={2} mb={2}>
                    <TextField 
                        label="Round" 
                        value={round} 
                        onChange={(e) => setRound(e.target.value)}
                        size="small"
                    />
                    <TextField 
                        label="Chain Hash (Hex)" 
                        value={chainHash} 
                        onChange={(e) => setChainHash(e.target.value)}
                        fullWidth
                        size="small"
                    />
                </Stack>

                <Button 
                    variant="contained" 
                    onClick={handleVerify}
                    disabled={!isWasmLoaded || loading}
                    startIcon={loading ? <CircularProgress size={20} /> : <LockIcon />}
                >
                    Verify Package
                </Button>

                {error && (
                    <Alert severity="error" sx={{ mt: 2 }}>
                        {error}
                    </Alert>
                )}

                {result && result.success && (
                    <Alert severity="success" sx={{ mt: 2 }} icon={<LockOpenIcon />}>
                        Verification Successful! Package is valid.
                    </Alert>
                )}
            </CardContent>
        </Card>
    );
}
