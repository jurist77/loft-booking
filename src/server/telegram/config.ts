import "server-only";
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { privateDirectory } from "../database.ts";
export type TelegramConfiguration = { token: string };
export function telegramConfigPath(databasePath: string, env = process.env): string {
  const file = env.TELEGRAM_CONFIG_FILE || resolve(dirname(databasePath), "settings/telegram-bot.json");
  if (!isAbsolute(file) || !relative(process.cwd(), resolve(/* turbopackIgnore: true */ file)).startsWith(`..${sep}`)) throw new Error("TELEGRAM_CONFIGURATION_INVALID"); return resolve(/* turbopackIgnore: true */ file);
}
export function loadTelegramConfiguration(file: string): TelegramConfiguration {
  try {
    privateDirectory(dirname(file)); const before = lstatSync(file);
    if (!before.isFile() || before.nlink !== 1 || (before.mode & 0o077) || before.uid !== process.getuid?.() || before.size > 4096) throw new Error();
    const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
    let text: string;
    try {
      const opened = fstatSync(fd); if (opened.dev !== before.dev || opened.ino !== before.ino) throw new Error();
      const buffer = Buffer.alloc(4097); const count = readSync(fd, buffer, 0, buffer.length, null);
      if (count > 4096) throw new Error(); text = buffer.subarray(0, count).toString("utf8");
    } finally { closeSync(fd); }
    const value = JSON.parse(text) as { version?: unknown; token?: unknown };
    if (!value || Object.keys(value).sort().join(",") !== "token,version" || value.version !== 1 || typeof value.token !== "string" || !/^\d{5,20}:[A-Za-z0-9_-]{20,200}$/.test(value.token)) throw new Error();
    return { token: value.token };
  } catch { throw new Error("TELEGRAM_CONFIGURATION_UNAVAILABLE"); }
}
