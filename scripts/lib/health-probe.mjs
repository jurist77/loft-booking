import { get } from "node:http";
import { setTimeout as delay } from "node:timers/promises";
import { performance } from "node:perf_hooks";

export class HealthProbeError extends Error {
  constructor(code) { super(code); this.name = "HealthProbeError"; this.code = code; }
}

// Each check has its own socket: no global fetch/Undici keep-alive pool.
export async function probeHealth(url, expectedStatus, timeoutMs) {
  return new Promise((resolve, reject) => {
    const request = get(url, { agent: false, headers: { Connection: "close" }, signal: AbortSignal.timeout(Math.max(1, Math.ceil(timeoutMs))) }, (response) => {
      let body = "";
      response.setEncoding("utf8");
      response.on("error", () => reject(new HealthProbeError("RESPONSE_CLOSED")));
      response.on("data", (chunk) => {
        body += chunk;
        if (body.length > 1024) request.destroy(new HealthProbeError("INVALID_RESPONSE"));
      });
      response.on("end", () => {
        // Never include response contents, headers or URLs in diagnostics.
        const status = response.statusCode;
        if (![200, 503].includes(status)) { reject(new HealthProbeError(`UNEXPECTED_HTTP_${status}`)); return; }
        const expectedBody = status === 200 ? '{"status":"ok"}' : '{"status":"unavailable"}';
        if (body !== expectedBody || response.headers["cache-control"] !== "no-store") { reject(new HealthProbeError("INVALID_RESPONSE")); return; }
        if (status !== expectedStatus) { reject(new HealthProbeError(`HTTP_${status}`)); return; }
        resolve();
      });
    });
    request.on("error", (error) => {
      if (error instanceof HealthProbeError) { reject(error); return; }
      const allowed = ["ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT", "ABORT_ERR"];
      reject(new HealthProbeError(allowed.includes(error.code) ? error.code : "HTTP_TRANSPORT_ERROR"));
    });
  });
}

export async function waitForHealth(url, { phase, expectedStatus, timeoutMs, assertAlive }) {
  const start = performance.now();
  const deadline = start + timeoutMs;
  let attempts = 0; let last = "NO_RESPONSE";
  while (performance.now() < deadline) {
    assertAlive();
    const attemptBudget = deadline - performance.now();
    // Do not replace the last real HTTP result with a meaningless 1ms abort at the deadline.
    if (attemptBudget < 100) { await delay(Math.max(0, attemptBudget)); break; }
    attempts++;
    try {
      await probeHealth(url, expectedStatus, Math.min(3000, deadline - performance.now()));
      assertAlive();
      console.log(`Health ${phase}: HTTP ${expectedStatus}; attempts=${attempts}; elapsedMs=${Math.round(performance.now() - start)}`);
      return;
    } catch (error) {
      assertAlive();
      if (!(error instanceof HealthProbeError)) throw error;
      last = error.code;
      // Wrong payload/status/headers is a defect, not a readiness delay.
      if (!["HTTP_200", "HTTP_503", "ECONNRESET", "ECONNREFUSED", "EPIPE", "ETIMEDOUT", "ABORT_ERR", "RESPONSE_CLOSED"].includes(last)) throw error;
    }
    const remaining = deadline - performance.now();
    if (remaining > 0) await delay(Math.min(200, remaining));
  }
  assertAlive();
  throw new HealthProbeError(`HEALTH_TIMEOUT phase=${phase} expected=${expectedStatus} attempts=${attempts} last=${last} elapsedMs=${Math.round(performance.now() - start)}`);
}
