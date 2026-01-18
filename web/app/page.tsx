import Verifier from '@/components/Verifier'
import { Container, Typography, Box } from '@mui/material'

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <Container maxWidth="lg">
        <Box sx={{ my: 4, textAlign: 'center' }}>
          <Typography variant="h2" component="h1" gutterBottom>
             VoidSwap TLock
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom color="text.secondary">
            Verifiable Timelock Encryption v0.2.1
          </Typography>
          <Verifier />
        </Box>
      </Container>
    </main>
  )
}
