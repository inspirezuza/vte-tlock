'use client';

import React, { useState, useEffect } from 'react';
import { 
  Box, 
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
        fetch('/vte.wasm'),
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

    useEffect(() => {
        loadWasm().then(() => setIsWasmLoaded(true)).catch(console.error);
    }, []);

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
                <Stack direction="row" alignItems="center" spacing={1} mb={2}>
                    <VerifiedUserIcon color="primary" fontSize="large" />
                    <Typography variant="h5" component="div">
                        VTE Verifier
                    </Typography>
                    {isWasmLoaded ? 
                        <Chip label="WASM Active" color="success" size="small" /> : 
                        <Chip label="Loading WASM..." color="warning" size="small" />
                    }
                </Stack>
                {/* 
                  TODO: Inputs for VTE Package, ChainHash, etc.
                  For simplicity, just a JSON area and a Verify button.
                 */}
                  
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
