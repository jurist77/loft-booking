import type { NextConfig } from "next";

const config: NextConfig = {
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
  ...(process.env.DEPLOY_TARGET === "pages" ? {
    output: "export",
    trailingSlash: true,
    images: { unoptimized: true },
  } : {}),
};

export default config;
