import "server-only";
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, fsyncSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { privateDirectory, privateFile } from "../database.ts";
export type TelegramConfiguration = { token: string; botId?: string; instance?: string; key?: string };
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
    const value = JSON.parse(text) as { version?: unknown; token?: unknown; botId?: unknown; instance?: unknown; key?: unknown };
    if (!value || typeof value.token !== "string" || !/^\d{5,20}:[A-Za-z0-9_-]{20,200}$/.test(value.token)) throw new Error();
    if (value.version === 1 && Object.keys(value).sort().join(",") === "token,version") return { token: value.token };
    if (value.version !== 2 || Object.keys(value).sort().join(",") !== "botId,instance,key,token,version" ||
        typeof value.botId !== "string" || !/^[0-9]{1,20}$/.test(value.botId) ||
        typeof value.instance !== "string" || !/^[a-f0-9]{64}$/.test(value.instance) ||
        typeof value.key !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(value.key)) throw new Error();
    return { token: value.token, botId: value.botId, instance: value.instance, key: value.key };
  } catch { throw new Error("TELEGRAM_CONFIGURATION_UNAVAILABLE"); }
}

export function telegramInstance(databasePath: string, create = false): string {
  const file = resolve(dirname(databasePath), ".telegram-instance");
  if (create) {
    privateDirectory(dirname(file));
    let fd: number | undefined;
    try { fd = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeFileSync(fd, randomBytes(32).toString("hex") + "\n"); fsyncSync(fd);
    } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw new Error("TELEGRAM_INSTANCE_UNAVAILABLE"); }
    finally { if (fd !== undefined) closeSync(fd); }
  }
  const identity = privateFile(file);
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    if (`${opened.dev}:${opened.ino}` !== identity) throw new Error("TELEGRAM_INSTANCE_UNAVAILABLE");
    const data = Buffer.alloc(129); const count = readSync(fd, data, 0, data.length, null); const value = data.subarray(0, count).toString("utf8").trim();
    if (!/^[a-f0-9]{64}$/.test(value)) throw new Error("TELEGRAM_INSTANCE_UNAVAILABLE");
    return createHash("sha256").update(value).digest("hex");
  } finally { closeSync(fd); }
}
export function saveTelegramConfiguration(file: string, config: Required<TelegramConfiguration>): void {
  privateDirectory(dirname(file), true);
  if ((lstatSync(dirname(file)).mode & 0o777) !== 0o700) throw new Error("TELEGRAM_CONFIGURATION_UNAVAILABLE");
  let previous: string | null = null;
  try { previous = privateFile(file); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const temporary = file + "." + randomBytes(16).toString("hex") + ".tmp";
  let created = false;
  try {
    const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); created = true;
    try { writeFileSync(fd, JSON.stringify({ version: 2, ...config }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    let current: string | null = null;
    try { current = privateFile(file); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
    if (current !== previous) throw new Error("TELEGRAM_CONFIGURATION_CHANGED");
    renameSync(temporary, file); created = false;
    const dir = openSync(dirname(file), constants.O_RDONLY); try { fsyncSync(dir); } finally { closeSync(dir); }
  } finally { if (created) try { unlinkSync(temporary); } catch {} }
}
