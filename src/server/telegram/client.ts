import "server-only";
import { request } from "node:https";

// Avoid Next's patched fetch/cache/tracing: Bot API paths contain the secret.
const nativeTelegramFetch: typeof fetch = (input, options) => new Promise((resolve, reject) => {
  let endpoint: URL;
  try {
    endpoint = new URL(String(input));
    if (endpoint.protocol !== "https:" || endpoint.hostname !== "api.telegram.org" || endpoint.port || endpoint.username || endpoint.password) throw new Error();
    const req = request(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, signal: options?.signal ?? undefined }, (res) => {
      let bytes = 0; const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => { bytes += chunk.length; if (bytes > 512 * 1024) req.destroy(); else chunks.push(chunk); });
      res.on("error", () => reject(new Error("TELEGRAM_TRANSPORT_FAILED")));
      res.on("aborted", () => reject(new Error("TELEGRAM_TRANSPORT_FAILED")));
      res.on("end", () => {
        try { resolve(new Response(Buffer.concat(chunks), { status: res.statusCode ?? 503 })); }
        catch { reject(new Error("TELEGRAM_TRANSPORT_FAILED")); }
      });
    });
    req.on("error", () => reject(new Error("TELEGRAM_TRANSPORT_FAILED")));
    req.end(String(options?.body ?? ""));
  } catch { reject(new Error("TELEGRAM_TRANSPORT_FAILED")); }
});

export type TelegramCode = "NETWORK_UNCERTAIN" | "RATE_LIMITED" | "AUTH_INVALID" | "RECIPIENT_UNREACHABLE" | "API_REJECTED" | "TEMPORARY_FAILURE" | "CONCURRENT_POLLING";
export type TelegramResult<T> = { ok: true; value: T } | { ok: false; code: TelegramCode; permanent: boolean; retryAfter: number };
export type TelegramUser = { id?: number; is_bot?: boolean; first_name?: string; last_name?: string; username?: string };
export type TelegramUpdate = { update_id: number; message?: { text?: string; from?: TelegramUser; chat?: { id?: number; type?: string } };
  callback_query?: { id?: string; data?: string; from?: TelegramUser; message?: { chat?: { id?: number; type?: string } } } };
export type TelegramMarkup = { inline_keyboard: { text: string; callback_data: string }[][] } | { keyboard: { text: string }[][]; resize_keyboard: boolean };
export interface TelegramTransport {
  getMe(signal?: AbortSignal): Promise<TelegramResult<{ id: number; username: string }>>;
  getUpdates(offset: number, signal?: AbortSignal): Promise<TelegramResult<TelegramUpdate[]>>;
  // MUST initiate the HTTP attempt synchronously, without an await before fetch.
  send(chatId: string, text: string, timeout: number, signal?: AbortSignal, markup?: TelegramMarkup): Promise<TelegramResult<number>>;
  webhookInfo?(): Promise<TelegramResult<{ url: string }>>;
  commands?(): Promise<TelegramResult<boolean>>;
  answerCallback?(id: string, signal?: AbortSignal): Promise<TelegramResult<boolean>>;
}
const uncertain = (): TelegramResult<never> => ({ ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 });
export class TelegramClient implements TelegramTransport {
  private readonly token: string;
  private readonly fetcher: typeof fetch;
  constructor(token: string, fetcher: typeof fetch = nativeTelegramFetch) {
    this.token = token; this.fetcher = fetcher;
    if (!/^\d{5,20}:[A-Za-z0-9_-]{20,200}$/.test(token)) throw new Error("TELEGRAM_CONFIGURATION_INVALID");
  }
  private request<T>(method: string, body: object, timeout: number, signal?: AbortSignal): Promise<TelegramResult<T>> {
    let promise: Promise<Response>;
    try {
      // Fixed official endpoint, verified TLS, no redirects or caller-supplied URL.
      promise = this.fetcher(`https://api.telegram.org/bot${this.token}/${method}`, { method: "POST", cache: "no-store", redirect: "error",
        headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
        signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout) });
    } catch { return Promise.resolve(uncertain()); }
    return promise.then(async (response): Promise<TelegramResult<T>> => {
      try {
        const reader = response.body?.getReader(); if (!reader) return uncertain();
        let bytes = 0; const chunks: Uint8Array[] = [];
        try {
          while (true) { const next = await reader.read(); if (next.done) break; bytes += next.value.length;
            if (bytes > 512 * 1024) { await reader.cancel(); return uncertain(); } chunks.push(next.value); }
        } finally { reader.releaseLock(); }
        const raw = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { ok?: unknown; result?: T; error_code?: unknown; parameters?: { retry_after?: unknown } };
        if (response.ok && raw.ok === true) return raw.result !== undefined ? { ok: true, value: raw.result } : uncertain();
        const code = Number(raw.error_code ?? response.status);
        if (!Number.isSafeInteger(code) || code < 400) return uncertain();
        const seconds = raw.parameters?.retry_after;
        if (code === 429) return { ok: false, code: "RATE_LIMITED", permanent: false,
          retryAfter: typeof seconds === "number" && Number.isSafeInteger(seconds) && seconds > 0 ? Math.min(seconds, 86400) * 1000 : 30000 };
        if (code === 401) return { ok: false, code: "AUTH_INVALID", permanent: true, retryAfter: 0 };
        if (code === 403) return { ok: false, code: "RECIPIENT_UNREACHABLE", permanent: true, retryAfter: 0 };
        if (code === 409) return { ok: false, code: "CONCURRENT_POLLING", permanent: true, retryAfter: 0 };
        if (code >= 500) return { ok: false, code: "TEMPORARY_FAILURE", permanent: false, retryAfter: 0 };
        return { ok: false, code: "API_REJECTED", permanent: true, retryAfter: 0 };
      } catch { return uncertain(); }
    }).catch(() => uncertain()); // Never expose fetch URLs/token, response descriptions or echoed message/contacts.
  }
  getMe(signal?: AbortSignal) { return this.request<{ id: number; username: string }>("getMe", {}, 8000, signal); }
  getUpdates(offset: number, signal?: AbortSignal) { return this.request<TelegramUpdate[]>("getUpdates", { offset, timeout: 20, limit: 50, allowed_updates: ["message", "callback_query"] }, 25000, signal); }
  webhookInfo() { return this.request<{ url: string }>("getWebhookInfo", {}, 8000); }
  commands() { return this.request<boolean>("setMyCommands", { commands: [{ command: "start", description: "Меню подписки" }, { command: "owner", description: "Владелец: меню или первое подключение" }] }, 8000); }
  answerCallback(id: string, signal?: AbortSignal) { return this.request<boolean>("answerCallbackQuery", { callback_query_id: id }, 5000, signal); }
  send(chatId: string, text: string, timeout: number, signal?: AbortSignal, markup?: TelegramMarkup) {
    return this.request<{ message_id: number }>("sendMessage", { chat_id: chatId, text, ...(markup ? { reply_markup: markup } : {}), link_preview_options: { is_disabled: true } }, timeout, signal)
      .then((r): TelegramResult<number> => r.ok ? (Number.isSafeInteger(r.value?.message_id) ? { ok: true, value: r.value.message_id } : uncertain()) : r);
  }
}
