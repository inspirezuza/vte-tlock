
'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
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
    Paper,
    Collapse
} from '@mui/material';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import AutoFixHighIcon from '@mui/icons-material/AutoFixHigh';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';
import ExpandLessIcon from '@mui/icons-material/ExpandLess';
import { DateTimePicker } from '@mui/x-date-pickers/DateTimePicker';
import { LocalizationProvider } from '@mui/x-date-pickers/LocalizationProvider';
import { AdapterDayjs } from '@mui/x-date-pickers/AdapterDayjs';
import dayjs, { Dayjs } from 'dayjs';
import vteClient from '@/lib/vte/client';

const steps = ['Context Mapping', 'Network Configuration', 'Secret Generation', 'Generate VTE'];

// Chain params interface
interface ChainParams {
    genesis_time: number;  // Unix timestamp (seconds)
    period: number;        // Seconds between rounds
    public_key: string;
    hash: string;
}

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
    const [chainHash, setChainHash] = useState('52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971');
    const [endpoints, setEndpoints] = useState(['https://api.drand.sh']);
    const [strategy, setStrategy] = useState<'gnark' | 'zkvm' | 'auto'>('auto');
    
    // Chain params (fetched from drand)
    const [chainParams, setChainParams] = useState<ChainParams | null>(null);
    const [chainParamsLoading, setChainParamsLoading] = useState(false);
    const [chainParamsError, setChainParamsError] = useState('');
    const [currentRound, setCurrentRound] = useState<number | null>(null);
    
    // Time-based unlock (new calendar approach)
    const [unlockDateTime, setUnlockDateTime] = useState<Dayjs | null>(null); // Dayjs object for DateTimePicker
    const [computedRound, setComputedRound] = useState<number | null>(null);
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [manualRound, setManualRound] = useState(''); // For advanced mode
    const [timeError, setTimeError] = useState('');
    const initialDateTimeSetRef = useRef(false); // Track if we've set initial datetime

    // Step 3: Secret
    const [r2, setR2] = useState('');
    const [R2, setR2Public] = useState(''); // R2 = r2 * G (public key)
    const [plaintextMode, setPlaintextMode] = useState(true);
    const [plaintextSecret, setPlaintextSecret] = useState('');

    // Step 4: Final
    const [vtePackage, setVtePackage] = useState<any>(null);

    // Fetch chain params on mount and when chainHash changes
    const fetchChainParams = useCallback(async () => {
        if (!chainHash) return;
        
        setChainParamsLoading(true);
        setChainParamsError('');
        
        try {
            const endpoint = endpoints[0] || 'https://api.drand.sh';
            const proxyUrl = typeof window !== 'undefined' 
                ? `${window.location.origin}/api/drand` 
                : endpoint;
            
            // Fetch chain info
            const infoResp = await fetch(`${proxyUrl}/${chainHash}/info`);
            if (!infoResp.ok) throw new Error(`Failed to fetch chain info: ${infoResp.status}`);
            const info: ChainParams = await infoResp.json();
            setChainParams(info);
            
            // Fetch latest round
            const latestResp = await fetch(`${proxyUrl}/${chainHash}/public/latest`);
            if (latestResp.ok) {
                const latest = await latestResp.json();
                setCurrentRound(latest.round);
            }
            
            // Set default unlock time to 5 minutes from now (only on first load)
            if (!initialDateTimeSetRef.current) {
                initialDateTimeSetRef.current = true;
                setUnlockDateTime(dayjs().add(5, 'minute'));
            }
            
        } catch (e: any) {
            setChainParamsError(e.message);
        } finally {
            setChainParamsLoading(false);
        }
    }, [chainHash, endpoints]);

    // Compute round from unlock datetime
    useEffect(() => {
        if (!chainParams || !unlockDateTime) {
            setComputedRound(null);
            return;
        }
        
        const unlockTimestamp = unlockDateTime.unix(); // Dayjs unix() returns seconds
        const now = dayjs().unix();
        
        // Validate: not in past
        if (unlockTimestamp < now) {
            setTimeError('Unlock time cannot be in the past');
            setComputedRound(null);
            return;
        }
        
        // Validate: minimum lead time (2 periods)
        const minLeadTime = 2 * chainParams.period;
        if (unlockTimestamp - now < minLeadTime) {
            setTimeError(`Minimum lead time is ${minLeadTime} seconds (~${Math.ceil(minLeadTime/60)} min)`);
            // Still compute but show warning
        } else {
            setTimeError('');
        }
        
        // Compute target round: ceil((unlock_time - genesis_time) / period)
        const targetRound = Math.ceil((unlockTimestamp - chainParams.genesis_time) / chainParams.period);
        setComputedRound(targetRound);
        
    }, [chainParams, unlockDateTime]);

    useEffect(() => {
        setMounted(true);
        vteClient.init()
            .then(() => setIsWasmLoaded(true))
            .catch(console.error);
    }, []);
    
    // Fetch chain params when component mounts
    useEffect(() => {
        if (mounted) {
            fetchChainParams();
        }
    }, [mounted, fetchChainParams]);

    if (!mounted) return null;

    const handleNext = async () => {
        setError('');
        try {
            if (activeStep === 0) {
                // Compute CtxHash
                // V2: CtxHash now depends on CapsuleHash (randomized encryption), 
                // so we cannot pre-compute it until generation.
                // We'll set a placeholder or skip it.
                setCtxHash('[Generated during encryption]');
            }
            if (activeStep === 1) {
                // Validate unlock time is set
                if (!showAdvanced && !computedRound) {
                    throw new Error("Please select a valid unlock time");
                }
                if (showAdvanced && !manualRound) {
                    throw new Error("Please enter a target round");
                }
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

    const generateRandomR2 = async () => {
        const bytes = new Uint8Array(32);
        window.crypto.getRandomValues(bytes);
        const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
        setR2(hex);
        
        // Compute R2 public key from r2 scalar
        if (isWasmLoaded) {
            try {
                const result = await vteClient.computeR2Point(hex);
                if (result.R2) {
                    setR2Public(result.R2);
                }
            } catch (e) {
                console.error('Failed to compute R2:', e);
            }
        }
    };

    const handleGenerateVTE = async () => {
        setLoading(true);
        setError('');
        try {
            const formatId = "tlock_v1_age_pairing"; // Standard for v0.2.1-age
            // Prepare endpoints
            const endpointList = endpoints; // `endpoints` is already an array
            let activeEndpoints = endpointList;
            
            // Use Proxy if in browser and targeting api.drand.sh
            if (typeof window !== 'undefined') {
                const proxyUrl = window.location.origin + '/api/drand';
                const needsProxy = endpointList.some(ep => ep.includes('api.drand.sh'));
                
                if (needsProxy) {
                    activeEndpoints = endpointList.map(ep => {
                        if (ep.includes('api.drand.sh')) return proxyUrl;
                        return ep;
                    });
                }
            }

            // Determine target round
            const targetRound = showAdvanced ? parseInt(manualRound) : computedRound!;

            const res = await vteClient.generateVTE({
                round: targetRound,
                chainHash,
                formatId: 'tlock_v1_age_pairing',
                r2: r2,
                refundTxHex: refundTx,
                sessionId: sessionId,
                endpoints: activeEndpoints,
                // canonicalEndpoints removed
                strategy: strategy
            });
            if (!res) throw new Error("No response from VTE worker");
            if (res.error) throw new Error(res.error);
            
            // Add metadata
            if (plaintextMode && plaintextSecret) {
                res.plaintext_hint = plaintextSecret;
            }
            if (unlockDateTime) {
                res.unlock_time_utc = unlockDateTime.toISOString();
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
                            Configure when the secret will be unlocked. The system will compute the target drand round.
                        </Typography>
                        
                        {/* Chain params loading/error */}
                        {chainParamsLoading && (
                            <Alert severity="info" icon={<CircularProgress size={16} />}>
                                Fetching drand chain parameters...
                            </Alert>
                        )}
                        {chainParamsError && (
                            <Alert severity="error">
                                Failed to fetch chain params: {chainParamsError}
                            </Alert>
                        )}
                        
                        {/* Unlock Time Picker */}
                        <Box>
                            <Typography variant="subtitle2" gutterBottom>Unlock Time</Typography>
                            <LocalizationProvider dateAdapter={AdapterDayjs}>
                                <DateTimePicker
                                    label="Unlock at"
                                    value={unlockDateTime}
                                    onChange={(newValue) => setUnlockDateTime(newValue)}
                                    disabled={showAdvanced}
                                    minDateTime={dayjs()}
                                    timeSteps={{ minutes: 1 }}
                                    slotProps={{
                                        textField: {
                                            fullWidth: true,
                                            helperText: timeError || "Click calendar icon to select date & time",
                                            error: !!timeError && timeError.includes('past')
                                        }
                                    }}
                                />
                            </LocalizationProvider>
                        </Box>
                        
                        {/* Preview Section */}
                        {chainParams && computedRound && !showAdvanced && (
                            <Paper sx={{ p: 2, bgcolor: 'rgba(0,200,255,0.05)', border: '1px solid rgba(0,200,255,0.2)' }}>
                                <Typography variant="subtitle2" color="primary" gutterBottom>
                                    📅 Unlock Preview
                                </Typography>
                                <Box sx={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 1, alignItems: 'center' }}>
                                    <Typography variant="caption" color="text.secondary">Unlock Time (UTC):</Typography>
                                    <Typography variant="body2" fontFamily="monospace">
                                        {unlockDateTime?.toDate().toUTCString()}
                                    </Typography>
                                    
                                    <Typography variant="caption" color="text.secondary">Computed Round:</Typography>
                                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                        <Typography variant="body2" fontFamily="monospace" fontWeight="bold" color="primary">
                                            {computedRound.toLocaleString()}
                                        </Typography>
                                        <Tooltip title="Copy round">
                                            <IconButton size="small" onClick={() => navigator.clipboard.writeText(computedRound.toString())}>
                                                <ContentCopyIcon fontSize="small" />
                                            </IconButton>
                                        </Tooltip>
                                    </Box>
                                    
                                    {currentRound && (
                                        <>
                                            <Typography variant="caption" color="text.secondary">Current Round:</Typography>
                                            <Typography variant="body2" fontFamily="monospace" color="text.secondary">
                                                ~{currentRound.toLocaleString()}
                                            </Typography>
                                        </>
                                    )}
                                    
                                    <Typography variant="caption" color="text.secondary">Period:</Typography>
                                    <Typography variant="body2" fontFamily="monospace" color="text.secondary">
                                        {chainParams.period}s per round
                                    </Typography>
                                </Box>
                            </Paper>
                        )}
                        
                        {/* Advanced Toggle */}
                        <Box>
                            <Button
                                size="small"
                                onClick={() => setShowAdvanced(!showAdvanced)}
                                endIcon={showAdvanced ? <ExpandLessIcon /> : <ExpandMoreIcon />}
                                sx={{ textTransform: 'none' }}
                            >
                                Advanced (manual round)
                            </Button>
                            <Collapse in={showAdvanced}>
                                <Stack spacing={2} sx={{ mt: 2, pl: 2, borderLeft: '2px solid rgba(255,255,255,0.1)' }}>
                                    <TextField
                                        label="Target Round (manual)"
                                        type="number"
                                        fullWidth
                                        value={manualRound}
                                        onChange={(e) => setManualRound(e.target.value)}
                                        helperText="For devs/auditors: specify exact drand round number"
                                    />
                                    <TextField
                                        label="Chain Hash (Hex)"
                                        fullWidth
                                        size="small"
                                        value={chainHash}
                                        onChange={(e) => setChainHash(e.target.value)}
                                    />
                                    <TextField
                                        label="Endpoints (Comma separated)"
                                        fullWidth
                                        size="small"
                                        value={endpoints.join(', ')}
                                        onChange={(e) => setEndpoints(e.target.value.split(',').map(s => s.trim()))}
                                    />
                                </Stack>
                            </Collapse>
                        </Box>
                        
                        {/* Proof Strategy */}
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
                        
                        {/* Show r2 (private) and R2 (public) results */}
                        {!plaintextMode && r2 && (
                            <Stack spacing={1}>
                                <Alert severity="warning" variant="outlined" sx={{ wordBreak: 'break-all' }}>
                                    <strong>r2 (Private Scalar):</strong> {r2.substring(0, 16)}...{r2.substring(r2.length - 8)}
                                    <Typography variant="caption" display="block" color="text.secondary">
                                        Keep this secret! This is your 32-byte private key.
                                    </Typography>
                                </Alert>
                                {R2 && (
                                    <Alert severity="success" variant="outlined" sx={{ wordBreak: 'break-all' }}>
                                        <strong>R2 (Public Key):</strong> {R2}
                                        <Typography variant="caption" display="block" color="text.secondary">
                                            R2 = r2 × G (secp256k1 point, 33 bytes compressed)
                                        </Typography>
                                    </Alert>
                                )}
                            </Stack>
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
                                {!showAdvanced && unlockDateTime && (
                                    <>
                                        <Typography variant="caption" color="primary">Unlock Time:</Typography>
                                        <Typography variant="caption" fontFamily="monospace">
                                            {unlockDateTime?.toDate().toUTCString()}
                                        </Typography>
                                    </>
                                )}
                                <Typography variant="caption" color="primary">Round:</Typography>
                                <Typography variant="caption" fontFamily="monospace">
                                    {showAdvanced ? manualRound : computedRound || 'Not set'}
                                </Typography>
                                {plaintextMode && (
                                    <>
                                        <Typography variant="caption" color="primary">Secret:</Typography>
                                        <Typography variant="caption" sx={{ wordBreak: 'break-all' }}>
                                            {plaintextSecret.substring(0, 30)}{plaintextSecret.length > 30 ? '...' : ''}
                                        </Typography>
                                    </>
                                )}
                                {/* Show R2 (public key) in review */}
                                <Typography variant="caption" color="primary">R2 (Public Key):</Typography>
                                <Typography variant="caption" sx={{ wordBreak: 'break-all', fontFamily: 'monospace', fontSize: '0.7rem' }}>
                                    {R2 ? R2 : 'Not computed'}
                                </Typography>
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
