
'use client';

import { Container, Typography, Box } from '@mui/material';

export default function DecryptPage() {
    return (
        <Container maxWidth="lg">
            <Box sx={{ my: 4 }}>
                <Typography variant="h4" component="h1" gutterBottom color="primary">
                    Decrypt & Reveal
                </Typography>
                <Typography color="text.secondary">
                    Wait for the time-lock round and decrypt the VTE package.
                </Typography>
                {/* Decrypt flow will go here */}
            </Box>
        </Container>
    );
}
