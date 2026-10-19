import { timeLabel, type Booking } from "./availability";
import { BookingClientError, type BookingRequest, type BookingService, type ServerConfirmation } from "./booking-service";
import { DEPLOYMENT } from "./deployment";
import { STUDIO } from "./studio";
import { validateContact } from "./validation";

const UNKNOWN = "Результат бронирования не удалось подтвердить. Заявка могла сохраниться. Повторите отправку: будет использован тот же номер заявки.";
const resourceIdDefault = "studio-19-25";
type Options = { resourceId?: string; basePath?: string; fetcher?: typeof fetch; uuid?: () => string; timeoutMs?: number };
function retryTime(value: string | null) {
  const seconds = value !== null && /^\d+$/.test(value) ? Number(value) : NaN;
  const at = Number.isFinite(seconds) ? Date.now() + seconds * 1000 : Date.parse(value ?? "");
  return Number.isSafeInteger(at) && at > Date.now() ? at : Date.now() + 60000;
}
const minutes = (value: unknown): number | null => typeof value === "string" && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value) ? Number(value.slice(0, 2)) * 60 + Number(value.slice(3)) : null;
const object = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};

/** Same-origin HTTP client. No server imports, browser storage, logging or automatic retries. */
export function createServerService({ resourceId = resourceIdDefault, basePath = DEPLOYMENT.basePath, fetcher = fetch, uuid = () => crypto.randomUUID(), timeoutMs = 10000 }: Options = {}): BookingService<ServerConfirmation> {
  if (basePath && !/^\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)*$/.test(basePath)) throw new Error("Invalid local API path");
  let attempt: { key: string; id: string; unknown: boolean; changeAllowed: boolean } | null = null;
  let sending = false; let postRetryAt = 0; let getRetryAt = 0;
  function canonical(request: BookingRequest) {
    const checked = validateContact(request.contact);
    if (Object.keys(checked.errors).length || !checked.phone) throw new BookingClientError("input", "Проверьте имя, фамилию и мобильный телефон.");
    return { resourceId, date: request.date, start: timeLabel(request.start), end: timeLabel(request.end), firstName: request.contact.firstName.trim(), lastName: request.contact.lastName.trim(), phone: checked.phone };
  }
  async function http(path: string, init: RequestInit, signal?: AbortSignal) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) controller.abort(); else signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, timeoutMs);
    try {
      const response = await fetcher(`${basePath}/api/${path}`, { ...init, cache: "no-store", credentials: "same-origin", mode: "same-origin", redirect: "error", signal: controller.signal });
      let payload: unknown;
      try { payload = await response.json(); } catch { payload = null; }
      return { response, data: object(payload) };
    } finally { clearTimeout(timer); signal?.removeEventListener("abort", abort); }
  }
  return {
    async getBookings(_now, date, signal) {
      if (!date) throw new BookingClientError("availability", "Выберите дату аренды.");
      if (Date.now() < getRetryAt) throw new BookingClientError("limited", "Слишком много запросов доступности. Подождите перед повтором.", getRetryAt);
      try {
        const { response, data } = await http(`availability?date=${encodeURIComponent(date)}&resourceId=${encodeURIComponent(resourceId)}`, { method: "GET" }, signal);
        if (response.status === 429) { getRetryAt = retryTime(response.headers.get("retry-after")); throw new BookingClientError("limited", "Слишком много запросов доступности. Подождите перед повтором.", getRetryAt); }
        if (!response.ok || data.date !== date || data.resourceId !== resourceId || data.timezone !== STUDIO.timeZone || !Array.isArray(data.busy) || data.busy.length > 28) throw new Error();
        return data.busy.map((value): Booking => {
          const interval = object(value); const start = minutes(interval.start); const end = minutes(interval.end);
          if (start === null || end === null || end <= start) throw new Error();
          return { date, start, end };
        });
      } catch (error) {
        if (signal?.aborted) throw error;
        if (error instanceof BookingClientError) throw error;
        throw new BookingClientError("availability", "Не удалось загрузить доступность. Свободное время пока не подтверждено. Попробуйте ещё раз.");
      }
    },
    isRetry(request) { return !!attempt?.unknown && attempt.key === JSON.stringify(canonical(request)); },
    acknowledgeChange() { if (attempt) attempt.changeAllowed = true; },
    reset() { if (!sending) attempt = null; },
    async confirm(request) {
      const body = canonical(request); const key = JSON.stringify(body);
      if (sending) throw new BookingClientError("unknown", "Заявка уже отправляется. Дождитесь ответа.", 0, true);
      if (Date.now() < postRetryAt) throw new BookingClientError("limited", "Слишком много запросов. Подождите перед повторной отправкой.", postRetryAt, attempt?.unknown);
      if (attempt?.unknown && attempt.key !== key && !attempt.changeAllowed) throw new BookingClientError("unknown", UNKNOWN, 0, true);
      if (!attempt || attempt.key !== key) attempt = { key, id: uuid(), unknown: false, changeAllowed: false };
      const current = attempt; sending = true;
      try {
        const { response, data } = await http("bookings", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ requestId: current.id, ...body }) });
        const code = object(data.error).code;
        if (response.status === 409 && code === "BOOKING_OVERLAP") { current.unknown = false; throw new BookingClientError("overlap", "Выбранный интервал уже занят. Выберите другое время."); }
        if (response.status === 429) { postRetryAt = retryTime(response.headers.get("retry-after")); throw new BookingClientError("limited", "Слишком много запросов. Подождите перед повторной отправкой.", postRetryAt, current.unknown); }
        if (response.status === 503 && response.headers.has("retry-after")) postRetryAt = retryTime(response.headers.get("retry-after"));
        if (response.status === 400) throw new BookingClientError("input", "Сервер отклонил данные. Проверьте дату, время, имя, фамилию и мобильный телефон.", 0, current.unknown);
        if (response.status === 403) throw new BookingClientError("input", "Не удалось разрешить отправку с этого адреса сайта. Свяжитесь с администратором.", 0, current.unknown);
        if (response.status === 404) throw new BookingClientError("input", "Студия сейчас недоступна для записи. Свяжитесь с администратором.", 0, current.unknown);
        if (response.status === 409) throw new BookingClientError("conflict", "Эту заявку нельзя подтвердить повторно. Номер не будет изменён автоматически. Свяжитесь с администратором.", 0, current.unknown);
        if (response.status !== 201 || data.bookingId !== current.id || data.status !== "confirmed" || data.date !== body.date || data.resourceId !== resourceId || data.start !== body.start || data.end !== body.end) throw new Error();
        current.unknown = false;
        return { date: body.date, start: request.start, end: request.end, bookingId: current.id, resourceId, demo: false };
      } catch (error) {
        if (error instanceof BookingClientError) throw error;
        current.unknown = true; current.changeAllowed = false;
        throw new BookingClientError("unknown", UNKNOWN, postRetryAt, true);
      } finally { sending = false; }
    },
  };
}
