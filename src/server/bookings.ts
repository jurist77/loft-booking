import "server-only";
import type Database from "better-sqlite3";
import { isBookableDate, isCalendarDate, timeLabel, validateInterval } from "../lib/availability.ts";
import { STUDIO } from "../lib/studio.ts";
import { validateContact, type ContactDetails } from "../lib/validation.ts";

export const STUDIO_RESOURCE_ID = "studio-19-25";
export type CreateBookingInput = ContactDetails & { id: string; resourceId: string; date: string; start: number; end: number };
export type StoredBooking = {
  id: string; resourceId: string; startsAt: number; endsAt: number; status: "confirmed" | "cancelled";
  // NULL is retained only for pre-0002 rows; no invented contacts or historic timestamps.
  firstName: string | null; lastName: string | null; phone: string | null;
  createdAt: number | null; updatedAt: number | null;
};
type BookingCode = "INVALID_INPUT" | "INVALID_DATE" | "INVALID_CONTACT" | "INVALID_INTERVAL" | "RESOURCE_NOT_FOUND" | "BOOKING_NOT_FOUND" | "BOOKING_ID_CONFLICT" | "BOOKING_OVERLAP" | "DATABASE_BUSY" | "STORAGE_FAILURE" | "TRANSACTION_ACTIVE";
export class BookingModelError extends Error {
  readonly code: BookingCode;
  constructor(code: BookingCode) { super(code); this.name = "BookingModelError"; this.code = code; }
}
const selectBooking = `SELECT id, resource_id AS resourceId, starts_at AS startsAt, ends_at AS endsAt, status,
  first_name AS firstName, last_name AS lastName, phone, created_at AS createdAt, updated_at AS updatedAt FROM bookings WHERE id = ?`;
export const isBookingIdentifier = (value: unknown): value is string => typeof value === "string" && value.length > 0 && value.length <= 128 && value.trim() === value && !/[\p{Cc}]/u.test(value);
function timestamp(now: Date): number {
  if (!(now instanceof Date) || !Number.isSafeInteger(now.getTime()) || now.getTime() < 0) throw new BookingModelError("INVALID_INPUT");
  return now.getTime();
}
function transaction<T>(db: Database.Database, work: () => T, mode: "immediate" | "deferred" = "immediate"): T {
  if (db.inTransaction) throw new BookingModelError("TRANSACTION_ACTIVE");
  try { return db.transaction(work)[mode](); }
  catch (error) {
    if (error instanceof BookingModelError) throw error;
    const native = error as { code?: string; message?: string };
    if (native.code?.startsWith("SQLITE_BUSY") || native.code?.startsWith("SQLITE_LOCKED")) throw new BookingModelError("DATABASE_BUSY");
    if (native.code === "SQLITE_CONSTRAINT_TRIGGER" && native.message === "BOOKING_OVERLAP") throw new BookingModelError("BOOKING_OVERLAP");
    // Never expose native SQL errors, paths or contact data.
    throw new BookingModelError("STORAGE_FAILURE");
  }
}

/** Internal model only. Caller reuses id for retry, uses a new id for a new request. */
export function createBooking(db: Database.Database, input: CreateBookingInput, now?: Date): StoredBooking {
  if (now !== undefined) timestamp(now);
  if (!input || !isBookingIdentifier(input.id) || !isBookingIdentifier(input.resourceId) || typeof input.date !== "string" || !isCalendarDate(input.date) ||
      !Number.isSafeInteger(input.start) || !Number.isSafeInteger(input.end) ||
      typeof input.firstName !== "string" || typeof input.lastName !== "string" || typeof input.phone !== "string") throw new BookingModelError("INVALID_INPUT");
  const contact = { firstName: input.firstName.trim(), lastName: input.lastName.trim(), phone: input.phone };
  const validation = validateContact(contact);
  if (Object.keys(validation.errors).length || !validation.phone) throw new BookingModelError("INVALID_CONTACT");
  const normalized = { ...contact, phone: validation.phone };
  // Same Moscow conversion as the existing availability rules; no machine-local timezone.
  const startsAt = Date.parse(`${input.date}T${timeLabel(input.start)}:00+03:00`);
  const endsAt = Date.parse(`${input.date}T${timeLabel(input.end)}:00+03:00`);
  if (![startsAt, endsAt].every(Number.isSafeInteger)) throw new BookingModelError("INVALID_INTERVAL");
  return transaction(db, () => {
    const existing = db.prepare(selectBooking).get(input.id) as StoredBooking | undefined;
    if (existing) {
      if (existing.resourceId !== input.resourceId || existing.startsAt !== startsAt || existing.endsAt !== endsAt ||
          existing.firstName !== normalized.firstName || existing.lastName !== normalized.lastName || existing.phone !== normalized.phone) throw new BookingModelError("BOOKING_ID_CONFLICT");
      // Replay is not a new booking: also works after the date passed or after cancellation.
      return existing;
    }
    // Read the server clock after acquiring the writer lock, not before waiting for it.
    const current = now ?? new Date(); const at = timestamp(current);
    if (validateInterval(input.date, input.start, input.end, [], current)) throw new BookingModelError("INVALID_INTERVAL");
    if (!db.prepare("SELECT id FROM resources WHERE id = ?").get(input.resourceId)) throw new BookingModelError("RESOURCE_NOT_FOUND");
    // The SQL trigger checks overlap under this writer lock; it also creates the event atomically.
    db.prepare(`INSERT INTO bookings(id, resource_id, starts_at, ends_at, first_name, last_name, phone, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(input.id, input.resourceId, startsAt, endsAt, normalized.firstName, normalized.lastName, normalized.phone, at, at);
    return db.prepare(selectBooking).get(input.id) as StoredBooking;
  });
}

/** Internal cancellation; future transport must provide authorization. No client API exists yet. */
export function cancelBooking(db: Database.Database, id: string, now?: Date): StoredBooking {
  if (!isBookingIdentifier(id)) throw new BookingModelError("INVALID_INPUT");
  if (now !== undefined) timestamp(now);
  return transaction(db, () => {
    const existing = db.prepare(selectBooking).get(id) as StoredBooking | undefined;
    if (!existing) throw new BookingModelError("BOOKING_NOT_FOUND");
    if (existing.status === "cancelled") return existing;
    const at = timestamp(now ?? new Date());
    if (at < (existing.updatedAt ?? existing.createdAt ?? 0)) throw new BookingModelError("INVALID_INPUT");
    db.prepare("UPDATE bookings SET status = 'cancelled', updated_at = ? WHERE id = ?").run(at, id);
    return db.prepare(selectBooking).get(id) as StoredBooking;
  });
}

/** Public availability contains only intervals; never select contacts or booking IDs. */
export function getAvailability(db: Database.Database, date: string, resourceId = STUDIO_RESOURCE_ID, now = new Date()) {
  timestamp(now);
  if (typeof date !== "string" || !isCalendarDate(date) || !isBookableDate(date, now)) throw new BookingModelError("INVALID_DATE");
  if (!isBookingIdentifier(resourceId)) throw new BookingModelError("INVALID_INPUT");
  const midnight = Date.parse(`${date}T00:00:00+03:00`);
  return transaction(db, () => {
    if (!db.prepare("SELECT id FROM resources WHERE id = ?").get(resourceId)) throw new BookingModelError("RESOURCE_NOT_FOUND");
    const intervals = db.prepare(`SELECT starts_at, ends_at FROM bookings
      WHERE resource_id = ? AND status = 'confirmed' AND starts_at < ? AND ends_at > ? ORDER BY starts_at`).all(resourceId, midnight + 86400000, midnight) as { starts_at: number; ends_at: number }[];
    return { date, resourceId, timezone: STUDIO.timeZone, busy: intervals.map((b) => ({ start: timeLabel((b.starts_at - midnight) / 60000), end: timeLabel((b.ends_at - midnight) / 60000) })) };
  }, "deferred");
}
