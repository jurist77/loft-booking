import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
const file = ".env.sqlite.local";
try {
  await writeFile(file, `# Local SQLite; never commit data or this file.\nAPP_MODE=server\nSQLITE_PATH=${resolve("..", ".studio1925-local", "studio.sqlite")}\nSQLITE_BUSY_TIMEOUT_MS=1000\n`, { flag: "wx", mode: 0o600 });
  console.log(`Created ${file}; database is outside the application checkout`);
} catch (error) { if (error.code !== "EEXIST") throw error; console.log(`Kept existing ${file} unchanged`); }
