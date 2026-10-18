import assert from "node:assert/strict";
import { readFile, readdir, stat } from "node:fs/promises";
import { resolve, relative, extname } from "node:path";
import { createHash } from "node:crypto";

const root = resolve("out");
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? "/loft-booking";
const secrets = [
  /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
  /\b(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|xox[baprs]-[A-Za-z0-9-]{15,}|AKIA[0-9A-Z]{16})\b/,
  /https?:\/\/[^\s/@:]+:[^\s/@]+@/,
];
let files = 0; let bytes = 0;
const fingerprint = createHash("sha256");
async function audit(folder) {
  for (const entry of (await readdir(folder, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const file = resolve(folder, entry.name);
    assert.ok(!entry.isSymbolicLink(), "Export must not contain symlinks");
    assert.ok(![".git", "node_modules", "docs", "e2e"].includes(entry.name) && !entry.name.startsWith(".env"), "Private/build source file in export");
    if (entry.isDirectory()) { await audit(file); continue; }
    assert.ok(!file.endsWith(".map"), "Browser source maps are not part of the public artifact");
    const data = await readFile(file); files++; bytes += data.length;
    fingerprint.update(relative(root, file)).update(data);
    if ([".html", ".js", ".css", ".json", ".txt", ".svg"].includes(extname(file))) {
      const text = data.toString();
      for (const rule of secrets) assert.ok(!rule.test(text), `Potential credential in ${relative(root, file)} (value suppressed)`);
      if (file.endsWith(".html")) {
        for (const match of text.matchAll(/(?:src|href)="([^"<>]+)"/g)) {
          const value = match[1].replaceAll("&amp;", "&");
          if (value.startsWith("#") || value.startsWith("tel:")) continue;
          assert.ok(value.startsWith("/") && !value.startsWith("//"), `Nonlocal asset/link: ${value}`);
          const pathname = value.split(/[?#]/)[0];
          assert.ok(!basePath || pathname.startsWith(`${basePath}/`), `Asset outside configured base path: ${pathname}`);
          let target = resolve(root, `.${decodeURIComponent(pathname.slice(basePath.length))}`);
          if ((await stat(target)).isDirectory()) target = resolve(target, "index.html");
          assert.ok((await stat(target)).isFile(), `Missing exported asset: ${pathname}`);
        }
      }
    }
  }
}
await stat(resolve(root, ".nojekyll"));
const html = await readFile(resolve(root, "index.html"), "utf8");
assert.ok(html.includes("Демонстрационная версия"));
assert.ok(html.includes("studio 19.25") && html.includes("/images/studio-19-25-logo.jpg"));
assert.ok(!/loft\s*studio/i.test(html));
assert.ok(html.includes('data-screen="welcome"'));
assert.ok(!html.includes('class="calendar"') && !html.includes('class="slots"'));
assert.ok(!html.includes("+79261234567") && !html.includes("Тест Пример"));
await audit(root);
console.log(JSON.stringify({ files, bytes, basePath, artifactSha256: fingerprint.digest("hex"), localAssetsExist: true, credentialPatternsFound: false, sourceMapsOrPrivateFiles: false }, null, 2));
