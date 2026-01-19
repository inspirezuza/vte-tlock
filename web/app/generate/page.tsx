
'use client';

import { Container } from '@mui/material';
import Generator from '@/components/Generator';

export default function GeneratePage() {
    return (
        <Container maxWidth="lg" sx={{ py: 4 }}>
            <Generator />
        </Container>
    );
}
