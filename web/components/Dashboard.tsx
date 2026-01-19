'use client';

import {
    Box,
    Container,
    Typography,
    Card,
    CardContent,
    Button,
    Stack,
    Chip,
    Grid,
    Paper,
    Divider
} from '@mui/material';
import LockClockIcon from '@mui/icons-material/LockClock';
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser';
import LockOpenIcon from '@mui/icons-material/LockOpen';
import CreateIcon from '@mui/icons-material/Create';
import ArrowForwardIcon from '@mui/icons-material/ArrowForward';
import SecurityIcon from '@mui/icons-material/Security';
import SpeedIcon from '@mui/icons-material/Speed';
import Link from 'next/link';

export default function Dashboard() {
    return (
        <Container maxWidth="lg" sx={{ py: 6 }}>
            {/* Hero Section */}
            <Box sx={{ textAlign: 'center', mb: 8 }}>
                <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
                    <LockClockIcon sx={{ fontSize: 80, color: 'primary.main' }} />
                </Box>
                <Typography variant="h2" fontWeight="bold" gutterBottom>
                    VTE-TLock
                </Typography>
                <Typography variant="h5" color="text.secondary" sx={{ mb: 3, maxWidth: 700, mx: 'auto' }}>
                    Verifiable Timelock Encryption with Zero-Knowledge Proofs
                </Typography>
                <Stack direction="row" spacing={1} justifyContent="center" sx={{ mb: 4 }}>
                    <Chip icon={<SecurityIcon />} label="Cryptographically Secure" color="primary" />
                    <Chip icon={<VerifiedUserIcon />} label="ZK Verified" color="success" />
                    <Chip icon={<SpeedIcon />} label="drand Powered" color="info" />
                </Stack>
                <Typography variant="body1" color="text.secondary" sx={{ maxWidth: 800, mx: 'auto', mb: 4 }}>
                    VTE-TLock enables you to encrypt secrets that can only be revealed after a specific time, 
                    with cryptographic proofs ensuring the encryption was done correctly. Perfect for atomic swaps, 
                    fair auctions, and time-based commitments.
                </Typography>
            </Box>

            {/* How It Works */}
            <Paper sx={{ p: 4, mb: 6, bgcolor: 'rgba(0, 255, 157, 0.05)', border: '1px solid rgba(0, 255, 157, 0.2)' }}>
                <Typography variant="h5" fontWeight="bold" gutterBottom color="primary">
                    How It Works
                </Typography>
                <Divider sx={{ my: 2 }} />
                <Stack spacing={3}>
                    <Box>
                        <Typography variant="h6" gutterBottom>1. Time-Based Encryption</Typography>
                        <Typography variant="body2" color="text.secondary">
                            Your secret is encrypted using Identity-Based Encryption (IBE) tied to a future drand beacon round. 
                            The encryption is time-locked: it cannot be decrypted until the drand network publishes that round's randomness.
                        </Typography>
                    </Box>
                    <Box>
                        <Typography variant="h6" gutterBottom>2. Zero-Knowledge Proofs</Typography>
                        <Typography variant="body2" color="text.secondary">
                            Two ZK proofs (SECP + TLE) cryptographically prove that your encryption was done correctly, 
                            binding your secret to the timelock without revealing it. This prevents cheating in protocols like atomic swaps.
                        </Typography>
                    </Box>
                    <Box>
                        <Typography variant="h6" gutterBottom>3. Guaranteed Reveal</Typography>
                        <Typography variant="body2" color="text.secondary">
                            After the target time, anyone can fetch the drand beacon and decrypt the package to recover your original secret. 
                            The decryption is deterministic and verifiable.
                        </Typography>
                    </Box>
                </Stack>
            </Paper>

            {/* Features Grid */}
            <Typography variant="h4" fontWeight="bold" sx={{ mb: 4, textAlign: 'center' }}>
                Three Ways to Use VTE-TLock
            </Typography>

            <Grid container spacing={4} sx={{ mb: 6 }}>
                {/* Generate */}
                <Grid item xs={12} md={4}>
                    <Card sx={{ 
                        height: '100%', 
                        display: 'flex', 
                        flexDirection: 'column',
                        transition: 'transform 0.2s',
                        '&:hover': { transform: 'translateY(-4px)' }
                    }}>
                        <CardContent sx={{ flexGrow: 1 }}>
                            <CreateIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
                            <Typography variant="h5" fontWeight="bold" gutterBottom>
                                Generate
                            </Typography>
                            <Typography variant="body2" color="text.secondary" paragraph>
                                Create time-locked packages with your secrets.
                            </Typography>
                            <Typography variant="caption" display="block" gutterBottom fontWeight="bold">Quick Steps:</Typography>
                            <Typography variant="caption" component="div" sx={{ color: 'text.secondary', mb: 2, lineHeight: 1.6 }}>
                                • Set context & unlock time<br/>
                                • Enter plaintext secret<br/>
                                • Choose proof strategy<br/>
                                • Generate package
                            </Typography>
                        </CardContent>
                        <Box sx={{ p: 2 }}>
                            <Button 
                                component={Link} 
                                href="/generate" 
                                variant="contained" 
                                fullWidth
                                endIcon={<ArrowForwardIcon />}
                            >
                                Start Generating
                            </Button>
                        </Box>
                    </Card>
                </Grid>

                {/* Verify */}
                <Grid item xs={12} md={4}>
                    <Card sx={{ 
                        height: '100%', 
                        display: 'flex', 
                        flexDirection: 'column',
                        transition: 'transform 0.2s',
                        '&:hover': { transform: 'translateY(-4px)' }
                    }}>
                        <CardContent sx={{ flexGrow: 1 }}>
                            <VerifiedUserIcon sx={{ fontSize: 48, color: 'success.main', mb: 2 }} />
                            <Typography variant="h5" fontWeight="bold" gutterBottom>
                                Verify
                            </Typography>
                            <Typography variant="body2" color="text.secondary" paragraph>
                                Audit packages for cryptographic validity.
                            </Typography>
                            <Typography variant="caption" display="block" gutterBottom fontWeight="bold">Verification Checks:</Typography>
                            <Typography variant="caption" component="div" sx={{ color: 'text.secondary', mb: 2, lineHeight: 1.6 }}>
                                ✓ Structural integrity<br/>
                                ✓ Network binding<br/>
                                ✓ Capsule binding<br/>
                                ✓ ZK proofs (SECP+TLE)
                            </Typography>
                        </CardContent>
                        <Box sx={{ p: 2 }}>
                            <Button 
                                component={Link} 
                                href="/verify" 
                                variant="outlined" 
                                fullWidth
                                endIcon={<ArrowForwardIcon />}
                            >
                                Verify Package
                            </Button>
                        </Box>
                    </Card>
                </Grid>

                {/* Decrypt */}
                <Grid item xs={12} md={4}>
                    <Card sx={{ 
                        height: '100%', 
                        display: 'flex', 
                        flexDirection: 'column',
                        transition: 'transform 0.2s',
                        '&:hover': { transform: 'translateY(-4px)' }
                    }}>
                        <CardContent sx={{ flexGrow: 1 }}>
                            <LockOpenIcon sx={{ fontSize: 48, color: 'warning.main', mb: 2 }} />
                            <Typography variant="h5" fontWeight="bold" gutterBottom>
                                Decrypt
                            </Typography>
                            <Typography variant="body2" color="text.secondary" paragraph>
                                Reveal secrets after timelock expires.
                            </Typography>
                            <Typography variant="caption" display="block" gutterBottom fontWeight="bold">How to Decrypt:</Typography>
                            <Typography variant="caption" component="div" sx={{ color: 'text.secondary', mb: 2, lineHeight: 1.6 }}>
                                • Wait for target round<br/>
                                • Load VTE package<br/>
                                • Fetch beacon & decrypt<br/>
                                • View plaintext secret
                            </Typography>
                        </CardContent>
                        <Box sx={{ p: 2 }}>
                            <Button 
                                component={Link} 
                                href="/decrypt" 
                                variant="outlined" 
                                fullWidth
                                color="warning"
                                endIcon={<ArrowForwardIcon />}
                            >
                                Decrypt Package
                            </Button>
                        </Box>
                    </Card>
                </Grid>
            </Grid>

            {/* Use Cases */}
            <Paper sx={{ p: 4, bgcolor: 'background.paper' }}>
                <Typography variant="h5" fontWeight="bold" gutterBottom>
                    Real-World Use Cases
                </Typography>
                <Divider sx={{ my: 2 }} />
                <Grid container spacing={3}>
                    <Grid item xs={12} md={6}>
                        <Box>
                            <Typography variant="h6" gutterBottom color="primary">💱 Atomic Swaps</Typography>
                            <Typography variant="body2" color="text.secondary">
                                Ensure fairness in cross-chain swaps by time-locking refund secrets. 
                                If one party doesn't cooperate, the other can reclaim their funds after a timeout.
                            </Typography>
                        </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Box>
                            <Typography variant="h6" gutterBottom color="primary">🎯 Sealed-Bid Auctions</Typography>
                            <Typography variant="body2" color="text.secondary">
                                Commit to bids without revealing them, then automatically reveal all bids at the deadline. 
                                Prevents bid sniping and ensures fair price discovery.
                            </Typography>
                        </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Box>
                            <Typography variant="h6" gutterBottom color="primary">🔐 Secret Sharing</Typography>
                            <Typography variant="body2" color="text.secondary">
                                Share sensitive information (passwords, keys) that should only be accessible after a certain date, 
                                like in a digital will or time-capsule.
                            </Typography>
                        </Box>
                    </Grid>
                    <Grid item xs={12} md={6}>
                        <Box>
                            <Typography variant="h6" gutterBottom color="primary">⚖️ Fair Protocols</Typography>
                            <Typography variant="body2" color="text.secondary">
                                Build trustless protocols requiring time-based commitments with cryptographic proof of correctness. 
                                Ideal for voting, lotteries, and more.
                            </Typography>
                        </Box>
                    </Grid>
                </Grid>
            </Paper>

            {/* Quick Start CTA */}
            <Box sx={{ textAlign: 'center', mt: 6 }}>
                <Typography variant="h5" fontWeight="bold" gutterBottom>
                    Ready to Get Started?
                </Typography>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 3 }}>
                    Try generating your first time-locked secret in under 2 minutes
                </Typography>
                <Button 
                    component={Link} 
                    href="/generate" 
                    variant="contained" 
                    size="large"
                    startIcon={<CreateIcon />}
                >
                    Generate Your First Package
                </Button>
            </Box>
        </Container>
    );
}
