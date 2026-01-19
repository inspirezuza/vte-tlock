
import { createTheme } from '@mui/material/styles';
import { Roboto } from 'next/font/google';

const roboto = Roboto({
  weight: ['300', '400', '500', '700'],
  subsets: ['latin'],
  display: 'swap',
});

const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00f0ff', // Cyan Neon
    },
    secondary: {
      main: '#7b2cbf', // Deep Purple
    },
    background: {
      default: '#050510', // Very dark blue/black
      paper: '#0A0A1F',   // Slightly lighter
    },
    text: {
      primary: '#e0e0ff',
      secondary: '#a0a0b0',
    },
    success: {
        main: '#00ff9d',
    },
    error: {
        main: '#ff0055',
    }
  },
  typography: {
    fontFamily: roboto.style.fontFamily,
    h1: { fontWeight: 700 },
    h2: { fontWeight: 700 },
    h3: { fontWeight: 600 },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiCard: {
        styleOverrides: {
            root: {
                backgroundImage: 'linear-gradient(145deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.01) 100%)',
                backdropFilter: 'blur(10px)',
                border: '1px solid rgba(255,255,255,0.1)',
            }
        }
    },
    MuiButton: {
        styleOverrides: {
            root: {
                textTransform: 'none',
                fontWeight: 600,
            }
        }
    }
  }
});

export default theme;
