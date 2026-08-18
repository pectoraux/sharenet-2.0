import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
  // Allow the sandbox preview panel + local origins to load Next.js dev assets.
  // The preview panel is served from *.space-z.ai and loads the dev server's
  // HMR / chunk assets cross-origin; without this Next.js 16 emits a warning
  // and (in a future major version) will refuse the request.
  allowedDevOrigins: [
    "*.space-z.ai",
    "localhost",
    "127.0.0.1",
  ],
};

export default nextConfig;
