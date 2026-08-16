import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "ShareNet 2.0 — First Deliverable",
  description:
    "Cross-platform, delay-tolerant distributed network. Protocol foundation + web control plane: canonical CBOR, Ed25519 identity, NodeAdvertisement, persistent sequence floors, waitlist/admin auth, demo accounts, architecture regression tests.",
  keywords: [
    "ShareNet",
    "mesh network",
    "delay-tolerant",
    "Ed25519",
    "canonical CBOR",
    "protocol",
    "delay tolerant network",
  ],
  authors: [{ name: "ShareNet 2.0" }],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
