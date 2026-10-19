import "server-only";
import { isCalendarDate } from "../lib/availability.ts";
import { isBookingIdentifier, type CreateBookingInput, STUDIO_RESOURCE_ID } from "./bookings.ts";
import { ApiError } from "./api-errors.ts";

export const MAX_BODY_BYTES = 4096;
export const BODY_TIMEOUT_MS = 5000;
export async function readJson(request: Request): Promise<unknown> {
  if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get("content-type") ?? "") ||
      ![null, "identity"].includes(request.headers.get("content-encoding"))) throw new ApiError("UNSUPPORTED_MEDIA_TYPE");
  const length = request.headers.get("content-length");
  if (length !== null && !/^\d+$/.test(length)) throw new ApiError("INVALID_INPUT");
  if (length !== null && Number(length) > MAX_BODY_BYTES) throw new ApiError("BODY_TOO_LARGE");
  if (!request.body) throw new ApiError("INVALID_JSON");
  const reader = request.body.getReader(); let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new ApiError("REQUEST_TIMEOUT")), BODY_TIMEOUT_MS); });
  try {
    const parts: Uint8Array[] = []; let size = 0;
    for (;;) {
      const { done, value } = await Promise.race([reader.read(), timeout]);
      if (done) break;
      size += value.byteLength; if (size > MAX_BODY_BYTES) throw new ApiError("BODY_TOO_LARGE"); parts.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const part of parts) { bytes.set(part, offset); offset += part.byteLength; }
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    const body: unknown = JSON.parse(text);
    // Contract is a flat string object. Reject duplicate keys (including escaped aliases),
    // rather than letting JSON.parse silently keep the last occurrence.
    const tokens = text.match(/"(?:\\[\s\S]|[^"\\])*"|[^\s]/gu) ?? [];
    const keys = new Set<string>();
    if (tokens[0] !== "{" || tokens.at(-1) !== "}" || tokens.length < 5 || (tokens.length - 1) % 4) throw new ApiError("INVALID_JSON");
    for (let i = 1; i < tokens.length - 1; i += 4) {
      if (!tokens[i].startsWith('"') || tokens[i + 1] !== ":" || !tokens[i + 2].startsWith('"') || tokens[i + 3] !== (i + 4 === tokens.length ? "}" : ",")) throw new ApiError("INVALID_JSON");
      const key: string = JSON.parse(tokens[i]); if (keys.has(key)) throw new ApiError("INVALID_JSON"); keys.add(key);
    }
    return body;
  } catch (error) { throw error instanceof ApiError ? error : new ApiError("INVALID_JSON"); }
  finally { clearTimeout(timer); void reader.cancel().catch(() => {}); try { reader.releaseLock(); } catch {} }
}

const fields = ["requestId", "resourceId", "date", "start", "end", "firstName", "lastName", "phone"] as const;
export function bookingInput(body: unknown): CreateBookingInput {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new ApiError("INVALID_INPUT");
  const value = body as Record<string, unknown>;
  if (Object.keys(value).length !== fields.length || fields.some((f) => typeof value[f] !== "string")) throw new ApiError("INVALID_INPUT");
  const v = value as Record<typeof fields[number], string>;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v.requestId) || !isBookingIdentifier(v.resourceId) || v.firstName.length > 80 || v.lastName.length > 80 || v.phone.length > 32) throw new ApiError("INVALID_INPUT");
  if (!isCalendarDate(v.date)) throw new ApiError("INVALID_DATE");
  const minutes = (time: string) => {
    if (!/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(time)) throw new ApiError("INVALID_TIME");
    return Number(time.slice(0, 2)) * 60 + Number(time.slice(3));
  };
  return { id: v.requestId.toLowerCase(), resourceId: v.resourceId, date: v.date, start: minutes(v.start), end: minutes(v.end), firstName: v.firstName, lastName: v.lastName, phone: v.phone };
}
export function availabilityInput(url: string) {
  if (url.length > 2048) throw new ApiError("INVALID_INPUT");
  const params = new URL(url).searchParams;
  if ([...params.keys()].some((key) => !["date", "resourceId"].includes(key)) || params.getAll("date").length !== 1 || params.getAll("resourceId").length > 1) throw new ApiError("INVALID_INPUT");
  const date = params.get("date")!;
  if (!isCalendarDate(date)) throw new ApiError("INVALID_DATE");
  const resourceId = params.get("resourceId") ?? STUDIO_RESOURCE_ID;
  if (!isBookingIdentifier(resourceId)) throw new ApiError("INVALID_INPUT");
  return { date, resourceId };
}
