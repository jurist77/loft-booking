import { expect, it, vi } from "vitest";
import { TelegramClient } from "./client";
import { bookingMessage } from "./format";
import type { StoredBooking } from "../bookings";

const token = "123456:" + "S".repeat(35); // synthetic, never sent to Telegram
it("uses only the official endpoint, no parse_mode/buttons or redirects, and suppresses echoed contacts/token", async () => {
  const fetcher = vi.fn<typeof fetch>(async () => new Response(JSON.stringify({ ok: false, error_code: 403, description: "synthetic phone "+token }), { status: 403 }));
  const result = await new TelegramClient(token, fetcher).send("111", "synthetic message", 5000);
  expect(result).toEqual({ ok: false, code: "RECIPIENT_UNREACHABLE", permanent: true, retryAfter: 0 });
  expect(JSON.stringify(result).includes(token)).toBe(false);
  const [url, options] = fetcher.mock.calls[0];
  expect(String(url).startsWith("https://api.telegram.org/bot")).toBe(true); expect(options?.redirect).toBe("error"); expect(options?.cache).toBe("no-store");
  const body = JSON.parse(String(options?.body)); expect(body.parse_mode).toBeUndefined(); expect(body.reply_markup).toBeUndefined(); expect(body.link_preview_options).toEqual({ is_disabled: true });
});
it("maps 429 retry_after, temporary and permanent errors without storing descriptions", async () => {
  for (const [status, code, permanent] of [[429, "RATE_LIMITED", false], [500, "TEMPORARY_FAILURE", false], [401, "AUTH_INVALID", true], [400, "API_REJECTED", true]] as const) {
    const fetcher: typeof fetch = async () => new Response(JSON.stringify({ ok: false, error_code: status, parameters: { retry_after: 37 }, description: token }), { status });
    const result = await new TelegramClient(token, fetcher).send("111", "fixture", 100);
    expect(result.ok).toBe(false); if (!result.ok) { expect(result.code).toBe(code); expect(result.permanent).toBe(permanent); if (status === 429) expect(result.retryAfter).toBe(37000); }
    expect(JSON.stringify(result).includes(token)).toBe(false);
  }
});
it("treats lost/malformed/oversized replies as uncertain instead of claiming non-delivery", async () => {
  const cases: (typeof fetch)[] = [async () => { throw new Error(token); }, async () => new Response('{'),
    async () => new Response(JSON.stringify({ ok: true })), async () => new Response("x".repeat(512 * 1024 + 1))];
  for (const fetcher of cases) {
    const result = await new TelegramClient(token, fetcher).send("111", "fixture", 100);
    expect(result).toEqual({ ok: false, code: "NETWORK_UNCERTAIN", permanent: false, retryAfter: 0 });
  }
});
it("formats Moscow time, duration and normalized phone as safe single-line plain-text values", () => {
  const value: StoredBooking = { id: "fixture", resourceId: "studio-19-25", status: "confirmed", startsAt: Date.parse("2030-11-15T11:00:00Z"), endsAt: Date.parse("2030-11-15T13:30:00Z"), firstName: "<b>Тест</b>\n📱 fake", lastName: "Пример\u202E", phone: "+79000000000", createdAt: 0, updatedAt: 0 };
  const text = bookingMessage(value);
  expect(text.includes("15.11.2030")).toBe(true); expect(text.includes("14:00–16:30")).toBe(true); expect(text.includes("2 часа 30 минут")).toBe(true);
  expect(text.includes("+7 900 000-00-00")).toBe(true); expect(text.includes("\u202E")).toBe(false);
  expect(text.includes("<b>Тест</b> 📱 fake Пример")).toBe(true);
});
