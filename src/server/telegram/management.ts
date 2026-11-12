import "server-only";
import { randomBytes } from "node:crypto";
import { lstatSync } from "node:fs";
import type Database from "better-sqlite3";
import { TelegramClient, type TelegramTransport } from "./client.ts";
import { loadTelegramConfiguration, saveTelegramConfiguration, telegramConfigPath, telegramInstance, type TelegramConfiguration } from "./config.ts";
import { digestToken, registerBot, telegramState, TelegramModelError } from "./model.ts";
import { confirmBootstrap } from "./interactions.ts";

export type TechnicalCommand = "plan" | "configure" | "bootstrap" | "diagnose";
export type TechnicalInput = { token?: string; confirmation?: string; expected?: { bot: string; instance: string; token: string } };
export function technicalStatus(db: Database.Database, path: string, now = Date.now()) {
  const state = telegramState(db); let config: TelegramConfiguration | undefined; let instance: string | undefined;
  try { config = loadTelegramConfiguration(telegramConfigPath(path)); } catch {}
  try { instance = telegramInstance(path); } catch {}
  const count = (sql: string) => (db.prepare(sql).get() as { n: number }).n;
  const error = (db.prepare("SELECT last_error FROM telegram_state WHERE id=1").get() as { last_error: string | null }).last_error;
  const workerLive = !!config && state.worker_config === digestToken(JSON.stringify(config)) && state.last_poll_at > now - 60000 && state.worker_until > now && !!state.worker_owner;
  const workerState = !config?.key ? "NOT_CONFIGURED" : instance !== config.instance ? "INSTANCE_MISMATCH" : workerLive ? "RUNNING" :
    error && ["AUTH_INVALID", "CONCURRENT_POLLING", "WORKER_UNAVAILABLE", "NETWORK_UNCERTAIN"].includes(error) ? error : "STARTING_OR_STOPPED";
  return { configured: !!config?.key, instanceBound: !!instance && instance === config?.instance,
    bot: config?.botId ? digestToken(config.botId) : null, instance: instance ?? null, token: config ? digestToken(config.token) : null,
    botRegistered: !!config?.botId && state.bot_id === config.botId, ownerReady: !!db.prepare(`SELECT 1 FROM telegram_state s JOIN telegram_recipients r ON r.id=s.owner_recipient_id WHERE s.id=1 AND r.connection_status='connected'`).get(),
    workerLive, workerState,
    enabled: !!state.enabled, subscribers: count("SELECT count(*) n FROM telegram_recipients WHERE active=1 AND connection_status='connected'"),
    pendingRequests: count("SELECT count(*) n FROM telegram_subscription_requests WHERE status='pending'"),
    queued: count("SELECT count(*) n FROM telegram_outbox WHERE status IN ('pending','sending')"),
    failed: count("SELECT count(*) n FROM telegram_outbox WHERE status='failed'") };
}
export async function manageTelegram(db: Database.Database, path: string, command: TechnicalCommand, input: TechnicalInput,
  client: (token: string) => TelegramTransport = (token) => new TelegramClient(token), now = Date.now()) {
  if (command === "diagnose") return technicalStatus(db, path, now);
  const file = telegramConfigPath(path);
  if (command === "bootstrap") {
    const config = loadTelegramConfiguration(file);
    if (!config.key || config.instance !== telegramInstance(path)) throw new TelegramModelError("INSTANCE_MISMATCH");
    confirmBootstrap(db, input.confirmation ?? "", now);
    return technicalStatus(db, path, now);
  }
  if (typeof input.token !== "string") throw new TelegramModelError("TOKEN_REQUIRED");
  const verified = await client(input.token).getMe();
  if (!verified.ok) throw new TelegramModelError(verified.code);
  const bot = verified.value;
  const webhook = await client(input.token).webhookInfo?.();
  if (!webhook?.ok || typeof webhook.value?.url !== "string") throw new TelegramModelError("WEBHOOK_STATE_UNCONFIRMED");
  if (webhook.value.url) throw new TelegramModelError("WEBHOOK_CONFIGURED");
  if (!Number.isSafeInteger(bot?.id) || bot.id <= 0 || typeof bot.username !== "string" || !/^[A-Za-z][A-Za-z0-9_]{4,31}$/.test(bot.username)) throw new TelegramModelError("INVALID_BOT_RESPONSE");
  const state = telegramState(db); let old: TelegramConfiguration | undefined;
  try { lstatSync(file); old = loadTelegramConfiguration(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  if ((state.bot_id && state.bot_id !== String(bot.id)) || (old && (old.botId ?? old.token.split(":")[0]) !== String(bot.id))) throw new TelegramModelError("BOT_CHANGED_RELINK_REQUIRED");
  // The host-local nonce is deliberately outside settings/SQLite backup.
  // Creating it is authorized technical setup, never a restored worker side effect.
  const instance = telegramInstance(path, true);
  const expected = { bot: digestToken(String(bot.id)), instance, token: digestToken(input.token) };
  if (command === "plan") return { ...technicalStatus(db, path, now), planned: expected };
  if (!input.expected || input.expected.bot !== expected.bot || input.expected.instance !== expected.instance || input.expected.token !== expected.token) throw new TelegramModelError("CONFIGURATION_PLAN_CHANGED");
  const config: Required<TelegramConfiguration> = { token: input.token, botId: String(bot.id), instance, key: old?.key ?? randomBytes(32).toString("base64url") };
  // No network wait in a SQLite transaction. Wrong tokens/bot IDs have already
  // failed before any configuration replacement; atomic rename never truncates.
  if (JSON.stringify(old) !== JSON.stringify(config)) saveTelegramConfiguration(file, config);
  registerBot(db, bot);
  return technicalStatus(db, path, now);
}
