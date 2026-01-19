
'use client';

import { useState, useEffect } from 'react';
import {
    Box,
    Stepper,
    Step,
    StepLabel,
    Button,
    Typography,
    Card,
    CardContent,
    TextField,
    Stack,
    Alert,
    CircularProgress,
    Chip,
    IconButton,
    Tooltip,
    Paper
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import vteClient from '@/lib/vte/client';

const steps = ['Context Mapping', 'Network Configuration', 'Secret Generation', 'Generate VTE'];

export default function Generator() {
    const [activeStep, setActiveStep] = useState(0);
    const [isWasmLoaded, setIsWasmLoaded] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [mounted, setMounted] = useState(false);

    // Step 1: Context
    const [sessionId, setSessionId] = useState('demo-session-123');
    const [refundTx, setRefundTx] = useState('0101010101010101010101010101010101010101010101010101010101010101');
    const [ctxHash, setCtxHash] = useState('');

    // Step 2: Network
    const [round, setRound] = useState('1000');
    const [chainHash, setChainHash] = useState('8990e7a9aaed2f2b79c43d7890f5a77042845c088af85050f28a25c13e53625f');
    const [endpoints, setEndpoints] = useState(['https://api.drand.sh']);
    const [strategy, setStrategy] = useState<'gnark' | 'zkvm' | 'auto'>('auto');
    
    // Time-based unlock
    const [useTime, setUseTime] = useState(true); // Use time instead of raw round
    const [unlockTime, setUnlockTime] = useState(''); // ISO datetime-local format
    const [duration, setDuration] = useState('60'); // Minutes from now

    // Step 3: Secret
    const [r2, setR2] = useState('');
    const [plaintextMode, setPlaintextMode] = useState(true); // New: use plaintext instead of hex
    const [plaintextSecret, setPlaintextSecret] = useState('');

    // Step 4: Final
    const [vtePackage, setVtePackage] = useState<any>(null);

    useEffect(() => {
        setMounted(true);
        vteClient.init()
            .then(() => setIsWasmLoaded(true))
            .catch(console.error);
    }, []);

    if (!mounted) return null;

    const handleNext = async () => {
        setError('');
        try {
            if (activeStep === 0) {
                // Compute CtxHash
                const hash = await vteClient.computeCtxHash(sessionId, refundTx);
                if (hash.error) throw new Error(hash.error);
                setCtxHash(hash);
            }
            if (activeStep === 1 && useTime) {
                // Calculate round from duration (minutes from now)
                // Quicknet: 3 second rounds, 20 rounds per minute
                const minutesFromNow = parseInt(duration);
                const roundsToAdd = minutesFromNow * 20; // 3s per round = 20 rounds/min
                const currentRound = 1000; // Mock current round
                const targetRound = currentRound + roundsToAdd;
                setRound(targetRound.toString());
            }
            if (activeStep === 2) {
                // Convert plaintext to hex r2 if needed
                if (plaintextMode) {
                    if (!plaintextSecret) throw new Error("Please enter a secret message");
                    // SHA256 hash the plaintext to get r2
                    const encoder = new TextEncoder();
                    const data = encoder.encode(plaintextSecret);
                    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    const r2Hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                    setR2(r2Hex);
                } else {
                    if (!r2) throw new Error("Please generate or enter a secret r2");
                }
            }
            setActiveStep((prev) => prev + 1);
        } catch (e: any) {
            setError(e.message);
        }
    };

    const handleBack = () => {
        setActiveStep((prev) => prev - 1);
    };

    const generateRandomR2 = () => {
        const bytes = new Uint8Array(32);
        window.crypto.getRandomValues(bytes);
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        setR2(hex);
    };

    const handleGenerateVTE = async () => {
        setLoading(true);
        setError('');
        try {
            const formatId = "tlock_v1_age_pairing"; // Standard for v0.2.1-age
            const res = await vteClient.generateVTE({
                round: parseInt(round),
                chainHash,
                formatId,
                r2,
                ctxHash,
                endpoints,
                strategy
            });
            if (res.error) throw new Error(res.error);
            
            // Add plaintext hint if using plaintext mode
            if (plaintextMode && plaintextSecret) {
                res.plaintext_hint = plaintextSecret;
                res.unlock_minutes = parseInt(duration);
            }
            
            setVtePackage(res);
        } catch (e: any) {
            setError(e.message);
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
    };

    const renderStepContent = (step: number) => {
        switch (step) {
            case 0:
                return (
                    <Stack spacing={3} sx={{ mt: 2 }}>
                        <Typography variant="body2" color="text.secondary">
                            Define the protocol context. The VTE will be cryptographically bound to these values.
                        </Typography>
                        <TextField
                            label="Session ID"
                            fullWidth
                            value={sessionId}
                            onChange={(e) => setSessionId(e.target.value)}
                        />
                        <TextField
                            label="Refund Transaction Hash (Hex)"
                            fullWidth
                            value={refundTx}
                            onChange={(e) => setRefundTx(e.target.value)}
                        />
                    </Stack>
                );
            case 1:
                return (
                    <Stack spacing={3} sx={{ mt: 2 }}>
                        <Typography variant="body2" color="text.secondary">
                            Configure the drand network, target round, and ZK proving strategy.
                        </Typography>
                        <TextField
                            label="Target Round"
                            type="number"
                            fullWidth
                            value={round}
                            onChange={(e) => setRound(e.target.value)}
                        />
                        <TextField
                            label="Chain Hash (Hex)"
                            fullWidth
                            value={chainHash}
                            onChange={(e) => setChainHash(e.target.value)}
                        />
                        <TextField
                            label="Endpoints (Comma separated)"
                            fullWidth
                            value={endpoints.join(', ')}
                            onChange={(e) => setEndpoints(e.target.value.split(',').map(s => s.trim()))}
                        />
                        
                        <Box>
                            <Typography variant="subtitle2" gutterBottom>Unlock Time</Typography>
                            <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
                                <Chip 
                                    label="Duration (Easy)" 
                                    color={useTime ? 'primary' : 'default'}
                                    onClick={() => setUseTime(true)}
                                    variant={useTime ? 'filled' : 'outlined'}
                                />
                                <Chip 
                                    label="Round Number" 
                                    color={!useTime ? 'primary' : 'default'}
                                    onClick={() => setUseTime(false)}
                                    variant={!useTime ? 'filled' : 'outlined'}
                                />
                            </Stack>
                            
                            {useTime ? (
                                <TextField
                                    label="Unlock in (minutes)"
                                    type="number"
                                    fullWidth
                                    value={duration}
                                    onChange={(e) => setDuration(e.target.value)}
                                    helperText="Secret will be revealed after this many minutes"
                                />
                            ) : (
                                <TextField
                                    label="Target Round"
                                    type="number"
                                    fullWidth
                                    value={round}
                                    onChange={(e) => setRound(e.target.value)}
                                    helperText="Advanced: Specify exact drand round number"
                                />
                            )}
                        </Box>
                        
                        <Box>
                            <Typography variant="subtitle2" gutterBottom>Proof Strategy</Typography>
                            <Stack direction="row" spacing={1}>
                                <Chip 
                                    label="Auto (Recommended)" 
                                    color={strategy === 'auto' ? 'primary' : 'default'}
                                    onClick={() => setStrategy('auto')}
                                    variant={strategy === 'auto' ? 'filled' : 'outlined'}
                                />
                                <Chip 
                                    label="Gnark (Track A)" 
                                    color={strategy === 'gnark' ? 'primary' : 'default'}
                                    onClick={() => setStrategy('gnark')}
                                    variant={strategy === 'gnark' ? 'filled' : 'outlined'}
                                />
                                <Chip 
                                    label="ZKVM (Track B)" 
                                    color={strategy === 'zkvm' ? 'warning' : 'default'}
                                    onClick={() => setStrategy('zkvm')}
                                    variant={strategy === 'zkvm' ? 'filled' : 'outlined'}
                                />
                            </Stack>
                            <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                                {strategy === 'auto' && 'System will auto-select the optimal proving method'}
                                {strategy === 'gnark' && 'Uses Gnark BN254 circuit (fastest, highest constraints)'}
                                {strategy === 'zkvm' && 'Uses ZKVM fallback (experimental, not yet implemented)'}
                            </Typography>
                        </Box>
                    </Stack>
                );
            case 2:
                return (
                    <Stack spacing={3} sx={{ mt: 2 }}>
                        <Typography variant="body2" color="text.secondary">
                            Enter the secret that will be time-locked.
                        </Typography>
                        
                        <Box>
                            <Typography variant="subtitle2" gutterBottom>Secret Type</Typography>
                            <Stack direction="row" spacing={1} sx={{ mb: 2 }}>
                                <Chip 
                                    label="Plaintext (Easy)" 
                                    color={plaintextMode ? 'primary' : 'default'}
                                    onClick={() => setPlaintextMode(true)}
                                    variant={plaintextMode ? 'filled' : 'outlined'}
                                />
                                <Chip 
                                    label="Hex (Advanced)" 
                                    color={!plaintextMode ? 'primary' : 'default'}
                                    onClick={() => setPlaintextMode(false)}
                                    variant={!plaintextMode ? 'filled' : 'outlined'}
                                />
                            </Stack>
                        </Box>

                        {plaintextMode ? (
                            <TextField
                                label="Secret Message"
                                fullWidth
                                value={plaintextSecret}
                                onChange={(e) => setPlaintextSecret(e.target.value)}
                                helperText="This message will be revealed after the unlock time"
                                multiline
                                rows={3}
                                placeholder="e.g., Hello from the future!"
                            />
                        ) : (
                            <Box sx={{ display: 'flex', gap: 1 }}>
                                <TextField
                                    label="Secret r2 (Hex)"
                                    fullWidth
                                    value={r2}
                                    onChange={(e) => setR2(e.target.value)}
                                    helperText="Must be 32 bytes (64 hex characters)"
                                />
                                <Tooltip title="Generate Random">
                                    <IconButton onClick={generateRandomR2} color="primary" sx={{ mt: 1 }}>
                                        <AutoFixHighIcon />
                                    </IconButton>
                                </Tooltip>
                            </Box>
                        )}
                        
                        {ctxHash && (
                            <Alert severity="info" variant="outlined">
                                CtxHash computed: {ctxHash.substring(0, 16)}...
                            </Alert>
                        )}
                    </Stack>
                );
            case 3:
                return (
                    <Stack spacing={3} sx={{ mt: 2 }}>
                        <Typography variant="body2" color="text.secondary">
                            Review parameters and generate the VTE Package.
                        </Typography>
                        <Paper sx={{ p: 2, bgcolor: 'background.default', border: '1px solid rgba(255,255,255,0.05)' }}>
                            <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 1 }}>
                                {useTime && (
                                    <>
                                        <Typography variant="caption" color="primary">Unlock In:</Typography>
                                        <Typography variant="caption">{duration} minutes</Typography>
                                    </>
                                )}
                                <Typography variant="caption" color="primary">Round:</Typography>
                                <Typography variant="caption">{round}</Typography>
                                {plaintextMode && (
                                    <>
                                        <Typography variant="caption" color="primary">Secret:</Typography>
                                        <Typography variant="caption" sx={{ wordBreak: 'break-all' }}>
                                            {plaintextSecret.substring(0, 30)}{plaintextSecret.length > 30 ? '...' : ''}
                                        </Typography>
                                    </>
                                )}
                                <Typography variant="caption" color="primary">CtxHash:</Typography>
                                <Typography variant="caption" sx={{ wordBreak: 'break-all' }}>{ctxHash}</Typography>
                            </Box>
                        </Paper>
                        {!vtePackage ? (
                            <Button
                                variant="contained"
                                onClick={handleGenerateVTE}
                                disabled={loading || !isWasmLoaded}
                                startIcon={loading ? <CircularProgress size={20} color="inherit" /> : <VerifiedUserIcon />}
                                fullWidth
                                size="large"
                            >
                                Generate & Prove
                            </Button>
                        ) : (
                            <Box>
                                <Alert severity="success" sx={{ mb: 2 }}>
                                    VTE Package Generated Successfully!
                                </Alert>
                                <TextField
                                    label="VTE Package JSON"
                                    multiline
                                    rows={8}
                                    fullWidth
                                    variant="outlined"
                                    value={JSON.stringify(vtePackage, null, 2)}
                                    InputProps={{
                                        readOnly: true,
                                        endAdornment: (
                                            <IconButton onClick={() => copyToClipboard(JSON.stringify(vtePackage, null, 2))}>
                                                <ContentCopyIcon fontSize="small" />
                                            </IconButton>
                                        )
                                    }}
                                />
                            </Box>
                        )}
                    </Stack>
                );
            default:
                return null;
        }
    };

    return (
        <Card sx={{ maxWidth: 800, mx: 'auto', mt: 4, position: 'relative' }}>
            <CardContent>
                <Box sx={{ mb: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="h5" color="primary" fontWeight="bold">
                        Create VTE Package
                    </Typography>
                    {isWasmLoaded ? 
                        <Chip label="Worker Ready" color="success" size="small" variant="outlined" /> : 
                        <Chip label="Initializing..." color="warning" size="small" variant="outlined" />
                    }
                </Box>

                <Stepper activeStep={activeStep} alternativeLabel sx={{ mb: 4 }}>
                    {steps.map((label) => (
                        <Step key={label}>
                            <StepLabel>{label}</StepLabel>
                        </Step>
                    ))}
                </Stepper>

                {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

                <Box sx={{ minHeight: 250 }}>
                    {renderStepContent(activeStep)}
                </Box>

                <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 4 }}>
                    <Button
                        disabled={activeStep === 0 || loading}
                        onClick={handleBack}
                    >
                        Back
                    </Button>
                    {activeStep < steps.length - 1 && (
                        <Button
                            variant="contained"
                            onClick={handleNext}
                            disabled={!isWasmLoaded}
                        >
                            Next
                        </Button>
                    )}
                </Box>
            </CardContent>
        </Card>
    );
}
