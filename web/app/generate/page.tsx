
'use client';

import { Container, Typography, Box } from '@mui/material';

export default function GeneratePage() {
    return (
        <Container maxWidth="lg">
            <Box sx={{ my: 4 }}>
                <Typography variant="h4" component="h1" gutterBottom color="primary">
                    Generate VTE Package
                </Typography>
                <Typography color="text.secondary">
                    Create a Verifiable Timelock Encryption package.
                </Typography>
                {/* Stepper will go here */}
            </Box>
        </Container>
    );
}
