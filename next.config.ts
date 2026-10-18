import type { NextConfig } from "next";
import { appMode } from "./src/lib/app-mode";

const mode = appMode(process.env.APP_MODE);
if (process.env.DEPLOY_TARGET === "pages" && mode !== "demo") throw new Error("Pages supports DEMO only");

const config: NextConfig = {
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  basePath: process.env.NEXT_PUBLIC_BASE_PATH || "",
  env: { NEXT_PUBLIC_APP_MODE: mode },
  pageExtensions: mode === "server" ? ["server.ts", "tsx", "ts", "jsx", "js"] : ["tsx", "ts", "jsx", "js"],
  ...(mode === "server" ? { distDir: ".next-server" } : {}),
  ...(process.env.DEPLOY_TARGET === "pages" ? {
    output: "export",
    trailingSlash: true,
    images: { unoptimized: true },
  } : {}),
};

export default config;
