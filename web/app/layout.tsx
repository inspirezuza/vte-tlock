import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import Script from 'next/script'; // Use Next.js Script for async loading
import ThemeRegistry from '@/components/ThemeRegistry';
import Navbar from '@/components/Navbar';

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'VTE-TLock Verifier',
  description: 'Verifiable Timelock Encryption Demo',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className} suppressHydrationWarning>
        <ThemeRegistry>
          <Script src="/wasm/wasm_exec.js" strategy="beforeInteractive" />
          <Navbar />
          {children}
        </ThemeRegistry>
      </body>
    </html>
  )
}
