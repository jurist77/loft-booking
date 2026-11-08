import { expect, it } from "vitest";
import { createServer, request } from "node:http";
import { connect } from "node:net";
import type { AddressInfo } from "node:net";
import { insecureBrowserProxy } from "../../scripts/lib/insecure-browser-proxy.mjs";

it("test proxy preserves the real browser Origin and cannot escape its fixed loopback upstream", async () => {
  const upstream = createServer((req, res) => res.end(JSON.stringify({ path: req.url, origin: req.headers.origin })));
  await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
  const local = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
  const origin = "http://192.0.2.10:3015"; const proxy = await insecureBrowserProxy(origin, local);
  const throughProxy = (url: string) => new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = request(proxy.url, { path: url, agent: false, headers: { Origin: origin } }, (res) => {
      let body = ""; res.on("data", (chunk) => { body += chunk; }); res.on("end", () => resolve({ status: res.statusCode!, body }));
    }); req.on("error", reject); req.end();
  });
  try {
    const response = await throughProxy(origin + "//example.invalid/path");
    expect(response.status).toBe(200); expect(JSON.parse(response.body)).toEqual({ path: "//example.invalid/path", origin });
    expect((await throughProxy("http://example.invalid/")).status).toBe(403);
    const denied = await new Promise<string>((resolve, reject) => {
      const socket = connect(Number(new URL(proxy.url).port), "127.0.0.1", () => socket.write("CONNECT example.invalid:443 HTTP/1.1\r\nHost: example.invalid\r\n\r\n"));
      let response = ""; socket.on("data", (chunk) => { response += chunk; }); socket.on("close", () => resolve(response)); socket.on("error", reject);
    });
    expect(denied).toBe("");
  } finally { await proxy.close(); await new Promise<void>((resolve) => upstream.close(() => resolve())); }
});
it("test proxy rejects non-fixture or non-loopback destinations before listening", async () => {
  await expect(insecureBrowserProxy("http://example.invalid", "http://127.0.0.1:3015")).rejects.toThrow("INVALID_BROWSER_FIXTURE_ORIGIN");
  await expect(insecureBrowserProxy("http://192.0.2.10:3015", "http://192.0.2.11:3015")).rejects.toThrow("INVALID_BROWSER_FIXTURE_ORIGIN");
});
