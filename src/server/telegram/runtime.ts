import "server-only";
import { databaseSettings } from "../config.ts";
import { openDatabase, privateFile } from "../database.ts";
import { TelegramClient } from "./client.ts";
import { loadTelegramConfiguration, telegramConfigPath } from "./config.ts";
import { TelegramModelError } from "./model.ts";
import { runTelegramSession } from "./worker.ts";

const registry = globalThis as typeof globalThis & { studioTelegram?: { stop: () => void; done: Promise<void> } };
const safeCodes = new Set(["AUTH_INVALID", "BOT_CHANGED_RELINK_REQUIRED", "WORKER_LEASE_LOST", "TELEGRAM_STORAGE_UNAVAILABLE", "INVALID_BOT_RESPONSE", "INVALID_UPDATE_RESPONSE"]);
function sleep(ms: number, signal: AbortSignal) {
  return new Promise<void>((resolve) => {
    if (signal.aborted) { resolve(); return; }
    const finish = () => { clearTimeout(timer); signal.removeEventListener("abort", finish); resolve(); };
    const timer = setTimeout(finish, ms); signal.addEventListener("abort", finish, { once: true });
  });
}
export function startTelegramRuntime(): void {
  if (process.env.APP_MODE !== "server" || process.env.STUDIO_TELEGRAM_WORKER !== "1" || registry.studioTelegram) return;
  const controller = new AbortController(); const stop = () => controller.abort();
  const done = (async () => {
    let lastCode = "";
    while (!controller.signal.aborted) {
      let db: ReturnType<typeof openDatabase> | undefined;
      let configured = false;
      try {
        const settings = databaseSettings(); const path = telegramConfigPath(settings.path);
        const config = loadTelegramConfiguration(path); configured = true;
        const identity = privateFile(settings.path); db = openDatabase(settings);
        const guard = () => {
          if (privateFile(settings.path) !== identity || loadTelegramConfiguration(path).token !== config.token) throw new Error("TELEGRAM_RUNTIME_REFRESH");
        };
        await runTelegramSession(db, new TelegramClient(config.token), controller.signal, guard);
        lastCode = "";
      } catch (error) {
        if (configured && !controller.signal.aborted) {
          const code = error instanceof TelegramModelError && safeCodes.has(error.code) ? error.code : "WORKER_UNAVAILABLE";
          if (lastCode !== code) console.warn("Telegram worker: " + code);
          lastCode = code;
          try { db?.prepare("UPDATE telegram_state SET last_error=?,last_error_at=? WHERE id=1").run(code, Date.now()); } catch {}
        }
      } finally { try { db?.close(); } catch {} }
      await sleep(configured ? 30000 : 5000, controller.signal);
    }
  })().catch(() => { /* No unhandled rejection/PII-bearing stack can stop Next. */ });
  registry.studioTelegram = { stop, done };
  process.once("SIGTERM", stop); process.once("SIGINT", stop);
}
export async function stopTelegramRuntime() { registry.studioTelegram?.stop(); await registry.studioTelegram?.done; delete registry.studioTelegram; }
