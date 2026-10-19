import "server-only";
import { isIP } from "node:net";
import { performance } from "node:perf_hooks";
import { ApiError } from "./api-errors.ts";

type Env = Record<string, string | undefined>;
export function apiSettings(env: Env = process.env) {
  try {
    const origin = env.API_PUBLIC_ORIGIN ?? "http://127.0.0.1:3000";
    const url = new URL(origin);
    const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
    if (url.origin !== origin || url.username || url.password || (url.protocol !== "https:" && !(loopback && url.protocol === "http:"))) throw new Error();
    if (env.API_TRUST_PROXY !== undefined && !["true", "false"].includes(env.API_TRUST_PROXY)) throw new Error();
    return { origin, trustProxy: env.API_TRUST_PROXY === "true" };
  } catch { throw new ApiError("API_UNAVAILABLE"); }
}
export function checkOrigin(request: Request, settings: ReturnType<typeof apiSettings>) {
  if (request.headers.get("origin") !== settings.origin ||
    (request.headers.has("sec-fetch-site") && request.headers.get("sec-fetch-site") !== "same-origin")) throw new ApiError("ORIGIN_NOT_ALLOWED");
}
export function clientKey(request: Request, settings: ReturnType<typeof apiSettings>) {
  // Next's Web Request has no authenticated peer socket. Never infer it from XFF/Host.
  if (!settings.trustProxy) return "shared";
  const ip = request.headers.get("x-studio-client-ip") ?? "";
  if (ip.length > 64 || ip.includes("%")) throw new ApiError("API_UNAVAILABLE");
  const version = isIP(ip);
  if (!version) throw new ApiError("API_UNAVAILABLE");
  return version === 6 ? new URL(`http://[${ip}]/`).hostname : ip;
}

const WINDOW_MS = 60000;
const budgets = { GET: { client: 60, total: 600 }, POST: { client: 10, total: 60 } };
type Bucket = { start: number; count: number };
/** Bounded, process-local fixed windows. No contacts, persistence, timers or extra service. */
export class ApiLimiter {
  private clients = new Map<string, Bucket>();
  private totals = new Map<string, Bucket>();
  check(method: "GET" | "POST", client: string, now = performance.now()) {
    for (const [key, value] of this.clients) if (now - value.start >= WINDOW_MS) this.clients.delete(key);
    const limit = budgets[method];
    const previous = this.totals.get(method);
    const total = !previous || now - previous.start >= WINDOW_MS ? { start: now, count: 0 } : previous;
    this.totals.set(method, total);
    const key = `${method}:${client}`;
    const bucket = this.clients.get(key) ?? { start: now, count: 0 };
    const retry = Math.max(1, Math.ceil((WINDOW_MS - (now - (total.count >= limit.total ? total.start : bucket.start))) / 1000));
    if (total.count >= limit.total || bucket.count >= limit.client || (!this.clients.has(key) && this.clients.size >= 1024)) throw new ApiError("RATE_LIMITED", retry);
    total.count++; bucket.count++; this.clients.set(key, bucket);
  }
}
const registry = globalThis as typeof globalThis & { studioApiLimiter?: ApiLimiter };
export function limitRequest(request: Request, settings: ReturnType<typeof apiSettings>, method: "GET" | "POST") {
  registry.studioApiLimiter ??= new ApiLimiter();
  registry.studioApiLimiter.check(method, clientKey(request, settings));
}
