import "server-only";
import { BookingModelError } from "./bookings.ts";
import { closeDatabase } from "./database.ts";

const errors = {
  INVALID_INPUT: [400, "Проверьте поля запроса"],
  INVALID_JSON: [400, "Ожидается корректный JSON-объект с текстовыми полями"],
  INVALID_DATE: [400, "Выберите допустимую дату в пределах трёх календарных месяцев"],
  INVALID_TIME: [400, "Укажите время в формате HH:MM"],
  INVALID_CONTACT: [400, "Проверьте имя, фамилию и мобильный телефон"],
  INVALID_INTERVAL: [400, "Интервал недопустим: проверьте дату, рабочие часы и продолжительность"],
  RESOURCE_NOT_FOUND: [404, "Ресурс не найден"],
  BOOKING_OVERLAP: [409, "Выбранное время уже занято"],
  BOOKING_ID_CONFLICT: [409, "Этот ID уже использован для другого запроса"],
  BOOKING_CANCELLED: [409, "Бронирование отменено и не может быть создано повторно с этим ID"],
  ORIGIN_NOT_ALLOWED: [403, "Источник запроса не разрешён"],
  BODY_TOO_LARGE: [413, "Размер запроса превышает допустимый"],
  UNSUPPORTED_MEDIA_TYPE: [415, "Используйте Content-Type application/json и UTF-8 без сжатия"],
  REQUEST_TIMEOUT: [408, "Время получения запроса истекло"],
  RATE_LIMITED: [429, "Слишком много запросов. Повторите позже"],
  DATABASE_BUSY: [503, "Хранилище временно занято. Повторите позже"],
  STORAGE_UNAVAILABLE: [503, "Хранилище временно недоступно"],
  API_UNAVAILABLE: [503, "API временно недоступен"],
  NOT_FOUND: [404, "Ресурс не найден"],
} as const;
export type ApiCode = keyof typeof errors;
export class ApiError extends Error {
  constructor(readonly code: ApiCode, readonly retryAfter?: number) { super(code); this.name = "ApiError"; }
}
export function apiJson(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(body, { status, headers: { "Cache-Control": "no-store, max-age=0", "X-Content-Type-Options": "nosniff", ...extra } });
}
export function apiFailure(error: unknown) {
  let safe = error instanceof ApiError ? error : new ApiError("STORAGE_UNAVAILABLE");
  if (error instanceof BookingModelError) {
    safe = new ApiError(error.code in errors ? error.code as ApiCode : "STORAGE_UNAVAILABLE");
  }
  if (safe.code === "STORAGE_UNAVAILABLE") closeDatabase();
  const [status, message] = errors[safe.code];
  return apiJson({ error: { code: safe.code, message } }, status,
    status === 429 || status === 503 ? { "Retry-After": String(safe.retryAfter ?? 1) } : {});
}
