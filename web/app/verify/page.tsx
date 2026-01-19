
'use client';

import { Container, Typography, Box } from '@mui/material';
import Verifier from '@/components/Verifier';

export default function VerifyPage() {
    return (
        <Container maxWidth="lg">
            <Box sx={{ my: 4 }}>
                <Typography variant="h4" component="h1" gutterBottom color="primary">
                    Verify VTE Package
                </Typography>
                <Typography color="text.secondary" sx={{ mb: 3 }}>
                    Strictly verify package integrity, network binding, and ZK proofs.
                </Typography>
                <Verifier />
            </Box>
        </Container>
    );
}
