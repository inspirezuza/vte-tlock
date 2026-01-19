'use client';

import { Container } from '@mui/material';
import Decryptor from '@/components/Decryptor';

export default function DecryptPage() {
    return (
        <Container maxWidth="lg" sx={{ py: 4 }}>
            <Decryptor />
        </Container>
    );
}
