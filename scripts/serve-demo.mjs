// Local verification server for exported files only. No API or booking backend.
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { resolve, sep, extname } from "node:path";

const root = resolve("out");
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "/loft-booking";
const port = Number(process.env.DEMO_PORT || 4173);
const mime = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml", ".json": "application/json", ".txt": "text/plain; charset=utf-8", ".ico": "image/x-icon", ".png": "image/png", ".woff2": "font/woff2" };

const server = createServer(async (request, response) => {
  if (!["GET", "HEAD"].includes(request.method || "")) { response.writeHead(405).end(); return; }
  try {
    const pathname = decodeURIComponent(new URL(request.url, "http://127.0.0.1").pathname);
    if (basePath && pathname === basePath) { response.writeHead(308, { Location: `${basePath}/` }).end(); return; }
    if (basePath && !pathname.startsWith(`${basePath}/`)) { response.writeHead(404).end(); return; }
    let file = resolve(root, `.${pathname.slice(basePath.length)}`);
    if (file !== root && !file.startsWith(root + sep)) { response.writeHead(403).end(); return; }
    if ((await stat(file)).isDirectory()) file = resolve(file, "index.html");
    const data = await readFile(file);
    response.writeHead(200, { "Content-Type": mime[extname(file)] || "application/octet-stream", "Cache-Control": "no-store" });
    response.end(request.method === "HEAD" ? undefined : data);
  } catch { response.writeHead(404).end(); }
});
server.listen(port, "127.0.0.1", () => console.log(`Static DEMO verification server: port ${port}, base path ${basePath || "/"}`));
