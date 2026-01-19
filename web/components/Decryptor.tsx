'use client';

import { useState, useEffect } from 'react';
import {
    Box,
    Card,
    CardContent,
    Typography,
    TextField,
    Button,
    Alert,
    Stack,
    Chip, CircularProgress
} from '@mui/material';
import LockClockIcon from '@mui/icons-material/LockClock';
import vteClient from '@/lib/vte/client';

export default function Decryptor() {
    const [isWasmLoaded, setIsWasmLoaded] = useState(false);
    const [vtePackage, setVtePackage] = useState('');
    const [decrypting, setDecrypting] = useState(false);
    const [result, setResult] = useState<{plaintext?: string; error?: string} | null>(null);
    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        vteClient.init()
            .then(() => setIsWasmLoaded(true))
            .catch(console.error);
    }, []);

    if (!mounted) return null;

    const handleDecrypt = async () => {
        setDecrypting(true);
        setResult(null);

        try {
            // Parse package
            const pkg = JSON.parse(vtePackage);
            
            // Call REAL decryption via WASM
            const decryptResult = await vteClient.decrypt(vtePackage);
            
            if (decryptResult.error) {
                throw new Error(decryptResult.error);
            }

            // Convert base64 plaintext to UTF-8 string
            const plaintextBytes = atob(decryptResult.plaintext);
            let plaintextStr = '';
            
            // Try to decode as UTF-8 text
            try {
                const decoder = new TextDecoder('utf-8');
                const bytes = new Uint8Array(plaintextBytes.length);
                for (let i = 0; i < plaintextBytes.length; i++) {
                    bytes[i] = plaintextBytes.charCodeAt(i);
                }
                plaintextStr = decoder.decode(bytes);
            } catch {
                // If not valid UTF-8, show as hex
                plaintextStr = Array.from(plaintextBytes)
                    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
                    .join('');
            }
            
            setResult({ plaintext: plaintextStr });
        } catch (e: any) {
            setResult({ error: e.message || 'Decryption failed' });
        } finally {
            setDecrypting(false);
        }
    };

    const loadSample = () => {
        const sample = {
            "round": 1000,
            "network_id": {
                "chain_hash": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "tlock_version": "v1.0.0",
                "ciphertext_format_id": "tlock_v1_age_pairing"
            },
            "capsule": "mock_encrypted_capsule",
            "plaintext_hint": "Hello from the future!"
        };
        setVtePackage(JSON.stringify(sample, null, 2));
    };

    return (
        <Stack spacing={3} sx={{ maxWidth: 800, mx: 'auto', mt: 4 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="h4" color="primary" fontWeight="bold">
                    Decrypt Timelock
                </Typography>
                {isWasmLoaded ? 
                    <Chip label="Ready" color="success" variant="outlined" /> : 
                    <Chip label="Initializing..." color="warning" variant="outlined" />
                }
            </Box>

            <Card>
                <CardContent>
                    <Stack spacing={3}>
                        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Typography variant="h6">VTE Package</Typography>
                            <Button size="small" onClick={loadSample}>Load Sample</Button>
                        </Box>

                        <TextField
                            label="VTE Package JSON"
                            multiline
                            rows={8}
                            fullWidth
                            value={vtePackage}
                            onChange={(e) => setVtePackage(e.target.value)}
                            sx={{ '& .MuiInputBase-root': { fontFamily: 'monospace', fontSize: '0.85rem' } }}
                        />

                        <Button
                            variant="contained"
                            size="large"
                            onClick={handleDecrypt}
                            disabled={!isWasmLoaded || decrypting || !vtePackage}
                            startIcon={decrypting ? <CircularProgress size={20} color="inherit" /> : <LockClockIcon />}
                        >
                            Fetch Beacon & Decrypt
                        </Button>

                        {result?.error && (
                            <Alert severity="error">{result.error}</Alert>
                        )}

                        {result?.plaintext && (
                            <Alert severity="success" sx={{ '& .MuiAlert-message': { width: '100%' } }}>
                                <Typography variant="subtitle2" gutterBottom>Decrypted Plaintext:</Typography>
                                <Typography 
                                    variant="h6" 
                                    sx={{ 
                                        fontFamily: 'monospace', 
                                        bgcolor: 'rgba(0,255,157,0.1)', 
                                        p: 2, 
                                        borderRadius: 1,
                                        wordBreak: 'break-all'
                                    }}
                                >
                                    {result.plaintext}
                                </Typography>
                            </Alert>
                        )}
                    </Stack>
                </CardContent>
            </Card>

            <Card sx={{ bgcolor: 'background.default', border: '1px solid rgba(255,255,255,0.05)' }}>
                <CardContent>
                    <Typography variant="subtitle2" gutterBottom color="primary">How it works</Typography>
                    <Typography variant="body2" color="text.secondary">
                        1. Wait for the specified round to be reached on the drand beacon<br/>
                        2. Fetch the beacon value for that round<br/>
                        3. Use the beacon to decrypt the timelock capsule<br/>
                        4. Extract and display the original plaintext secret
                    </Typography>
                </CardContent>
            </Card>
        </Stack>
    );
}
