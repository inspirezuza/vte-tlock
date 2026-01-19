
'use client';

import AppBar from '@mui/material/AppBar';
import Box from '@mui/material/Box';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';
import Button from '@mui/material/Button';
import { usePathname, useRouter } from 'next/navigation';
import LockIcon from '@mui/icons-material/Lock';
import Container from '@mui/material/Container';

const pages = [
  { name: 'Dashboard', path: '/' },
  { name: 'Generate', path: '/generate' },
  { name: 'Verify', path: '/verify' },
  { name: 'Decrypt', path: '/decrypt' },
];

export default function Navbar() {
  const router = useRouter();
  const pathname = usePathname();

  return (
    <AppBar position="static" color="transparent" elevation={0} sx={{ borderBottom: '1px solid rgba(255,255,255,0.1)' }}>
      <Container maxWidth="xl">
        <Toolbar disableGutters>
          <LockIcon sx={{ display: { xs: 'none', md: 'flex' }, mr: 1, color: 'primary.main' }} />
          <Typography
            variant="h6"
            noWrap
            component="a"
            href="/"
            sx={{
              mr: 2,
              display: { xs: 'none', md: 'flex' },
              fontFamily: 'monospace',
              fontWeight: 700,
              letterSpacing: '.3rem',
              color: 'inherit',
              textDecoration: 'none',
              background: 'linear-gradient(45deg, #00f0ff 30%, #7b2cbf 90%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent'
            }}
          >
            VTE
          </Typography>

          <Box sx={{ flexGrow: 1, display: 'flex', gap: 2 }}>
            {pages.map((page) => {
              const isActive = pathname === page.path;
              return (
                <Button
                  key={page.name}
                  onClick={() => router.push(page.path)}
                  sx={{
                    my: 2,
                    color: isActive ? 'primary.main' : 'text.secondary',
                    display: 'block',
                    borderBottom: isActive ? '2px solid #00f0ff' : '2px solid transparent',
                    borderRadius: 0,
                    '&:hover': {
                        color: 'primary.main',
                        backgroundColor: 'rgba(0, 240, 255, 0.05)'
                    }
                  }}
                >
                  {page.name}
                </Button>
              );
            })}
          </Box>
        </Toolbar>
      </Container>
    </AppBar>
  );
}
