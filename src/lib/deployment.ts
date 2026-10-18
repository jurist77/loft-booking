import { appMode, type AppMode } from "./app-mode";
export type { AppMode } from "./app-mode";
export type DeploymentConfig = { mode: AppMode; basePath: string; apiBaseUrl: string };

export function deploymentConfig(input: { mode?: string; basePath?: string; apiBaseUrl?: string }): DeploymentConfig {
  const mode = appMode(input.mode);
  const basePath = input.basePath || "";
  if (basePath && !/^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(basePath)) {
    throw new Error("Base path must be empty or an absolute path without a trailing slash");
  }
  const apiBaseUrl = input.apiBaseUrl || "";
  if (apiBaseUrl && !apiBaseUrl.startsWith("/") && !/^https?:\/\//.test(apiBaseUrl)) {
    throw new Error("API base URL must be relative or use HTTP(S)");
  }
  return { mode, basePath, apiBaseUrl };
}

// NEXT_PUBLIC values are public build configuration, never credentials.
export const DEPLOYMENT = deploymentConfig({
  mode: process.env.NEXT_PUBLIC_APP_MODE,
  basePath: process.env.NEXT_PUBLIC_BASE_PATH,
  apiBaseUrl: process.env.NEXT_PUBLIC_API_BASE_URL,
});

export function assetPath(path: string, basePath = DEPLOYMENT.basePath): string {
  if (!path.startsWith("/") || path.startsWith("//")) throw new Error("Expected a local absolute asset path");
  return `${basePath}${path}`;
}
