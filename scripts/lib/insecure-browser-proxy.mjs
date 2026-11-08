import { createServer, request } from "node:http";
import { createConnection } from "node:net";

/** Test fixture only: an HTTP TEST-NET origin in Chromium, forwarded exclusively
 * to our loopback Next process. No real VPS/public network connection is made.
 * Keep Origin/Host unchanged so the real API's same-origin validation still runs.
 */
export async function insecureBrowserProxy(publicOrigin, backendOrigin) {
  const publicUrl = new URL(publicOrigin); const backend = new URL(backendOrigin);
  const connections = new Set();
  if (publicUrl.origin !== publicOrigin || backend.origin !== backendOrigin || publicUrl.hostname !== "192.0.2.10" || publicUrl.protocol !== "http:" || backend.hostname !== "127.0.0.1" || backend.protocol !== "http:") throw new Error("INVALID_BROWSER_FIXTURE_ORIGIN");
  const proxy = createServer((incoming, outgoing) => {
    let target;
    try { target = new URL(incoming.url); } catch { outgoing.writeHead(400).end(); return; }
    if (target.origin !== publicOrigin) { outgoing.writeHead(403).end(); return; }
    const destination = new URL(backend); destination.pathname = target.pathname; destination.search = target.search;
    const upstream = request(destination, { method: incoming.method, headers: incoming.headers, agent: false, timeout: 10000 }, (response) => {
      outgoing.writeHead(response.statusCode, response.headers); response.pipe(outgoing);
    });
    upstream.on("timeout", () => upstream.destroy());
    upstream.on("error", () => { if (!outgoing.headersSent) outgoing.writeHead(502); outgoing.end(); });
    incoming.on("aborted", () => upstream.destroy()); outgoing.on("close", () => upstream.destroy());
    incoming.pipe(upstream);
  });
  const track = (socket) => { connections.add(socket); socket.once("close", () => connections.delete(socket)); };
  proxy.on("connection", track);
  // Playwright's Node route.fetch uses CONNECT even for an HTTP destination.
  // Accept only the fixture authority and tunnel only to the fixed loopback.
  proxy.on("connect", (incoming, socket, head) => {
    if (incoming.url !== publicUrl.host) { socket.destroy(); return; }
    const upstream = createConnection({ host: "127.0.0.1", port: Number(backend.port || 80) }); track(upstream);
    upstream.setTimeout(10000, () => upstream.destroy());
    upstream.on("error", () => socket.destroy()); socket.on("error", () => upstream.destroy());
    socket.once("close", () => upstream.destroy()); upstream.once("close", () => socket.destroy());
    upstream.once("connect", () => { socket.write("HTTP/1.1 200 Connection Established\r\n\r\n"); if (head.length) upstream.write(head); socket.pipe(upstream); upstream.pipe(socket); });
  });
  await new Promise((resolve, reject) => { proxy.once("error", reject); proxy.listen(0, "127.0.0.1", resolve); });
  return {
    url: `http://127.0.0.1:${proxy.address().port}`,
    async close() { await new Promise((resolve) => { proxy.close(resolve); for (const socket of connections) socket.destroy(); proxy.closeAllConnections(); }); },
  };
}
