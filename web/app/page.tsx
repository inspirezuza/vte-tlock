import { Container, Typography, Box } from '@mui/material'

export default function Home() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-between p-24">
      <Container maxWidth="lg">
        <Box sx={{ my: 4, textAlign: 'center' }}>
          <Typography variant="h2" component="h1" gutterBottom sx={{ 
              background: 'linear-gradient(45deg, #00f0ff 30%, #7b2cbf 90%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
          }}>
             VoidSwap TLock
          </Typography>
          <Typography variant="h5" component="h2" gutterBottom color="text.secondary">
            Verifiable Timelock Encryption v0.2.1
          </Typography>
          
          {/* Dashboard Metrics / Quick Links */}
          <Box sx={{ display: 'flex', gap: 2, justifyContent: 'center', mt: 4 }}>
             {/* Temporary Links */}
          </Box>
        </Box>
      </Container>
    </main>
  )
}
