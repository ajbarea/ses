import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "export",
  trailingSlash: true,
  assetPrefix: "/",
  allowedDevOrigins: [
    "192.168.0.164",
    "192.168.0.164:3000",
  ],
};

export default nextConfig;
