import { STUDIO } from "./studio";

/** Dates are ISO calendar dates in Moscow; intervals are half-open [start, end). */
export type Booking = { date: string; start: number; end: number };
export type Slot = { start: number; busy: boolean; past: boolean };
const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;

export function isCalendarDate(date: string): boolean {
  if (!ISO_DATE.test(date)) return false;
  const parsed = new Date(`${date}T12:00:00Z`);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString().slice(0, 10) === date;
}

export function moscowDate(now = new Date()): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: STUDIO.timeZone, year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(now);
  const part = (type: string) => parts.find((p) => p.type === type)!.value;
  return `${part("year")}-${part("month")}-${part("day")}`;
}

export function addDays(date: string, days: number): string {
  const value = new Date(`${date}T12:00:00Z`);
  value.setUTCDate(value.getUTCDate() + days);
  return value.toISOString().slice(0, 10);
}

export function addMonths(date: string, months: number): string {
  const value = new Date(`${date}T12:00:00Z`);
  const day = value.getUTCDate();
  value.setUTCDate(1);
  value.setUTCMonth(value.getUTCMonth() + months);
  const last = new Date(Date.UTC(value.getUTCFullYear(), value.getUTCMonth() + 1, 0)).getUTCDate();
  value.setUTCDate(Math.min(day, last));
  return value.toISOString().slice(0, 10);
}

export function dateRange(now = new Date()) {
  const first = moscowDate(now);
  return { first, last: addMonths(first, STUDIO.monthsAhead) };
}

export function isBookableDate(date: string, now = new Date()): boolean {
  const { first, last } = dateRange(now);
  return isCalendarDate(date) && date >= first && date <= last;
}

export function timeLabel(minutes: number): string {
  return `${Math.floor(minutes / 60).toString().padStart(2, "0")}:${(minutes % 60).toString().padStart(2, "0")}`;
}

export function formatDate(date: string, options: Intl.DateTimeFormatOptions = { day: "numeric", month: "long" }): string {
  return new Intl.DateTimeFormat("ru-RU", { ...options, timeZone: "UTC" }).format(new Date(`${date}T12:00:00Z`));
}

export function durationLabel(minutes: number): string {
  const hours = Math.floor(minutes / 60);
  const rest = minutes % 60;
  return [hours ? `${hours} ч` : "", rest ? `${rest} мин` : ""].filter(Boolean).join(" ");
}

export function overlaps(a: Pick<Booking, "start" | "end">, b: Pick<Booking, "start" | "end">): boolean {
  return a.start < b.end && b.start < a.end;
}

function isPast(date: string, minutes: number, now: Date): boolean {
  // Europe/Moscow has UTC+03:00 throughout the supported booking horizon.
  return new Date(`${date}T${timeLabel(minutes)}:00+03:00`).getTime() < now.getTime();
}

export function getSlots(date: string, bookings: readonly Booking[], now = new Date()): Slot[] {
  return Array.from({ length: (STUDIO.close - STUDIO.open) / STUDIO.step }, (_, i) => {
    const start = STUDIO.open + i * STUDIO.step;
    return {
      start,
      busy: bookings.some((b) => b.date === date && overlaps({ start, end: start + STUDIO.step }, b)),
      past: !isBookableDate(date, now) || isPast(date, start, now),
    };
  });
}

export function validateInterval(date: string, start: number, end: number, bookings: readonly Booking[], now = new Date()): string | null {
  if (!isBookableDate(date, now)) return "Выберите дату от сегодняшнего дня до трёх месяцев вперёд.";
  if (![start, end].every(Number.isFinite) || start % STUDIO.step || end % STUDIO.step) return "Выберите время с шагом 30 минут.";
  if (start < STUDIO.open || end > STUDIO.close) return `Студия открыта с ${timeLabel(STUDIO.open)} до ${timeLabel(STUDIO.close)}.`;
  if (end - start < STUDIO.minimum) return "Минимальная продолжительность аренды — 60 минут.";
  if (isPast(date, start, now)) return "Это время уже прошло. Выберите другое время начала.";
  if (bookings.some((b) => b.date === date && overlaps({ start, end }, b))) return "Это время уже занято. Выберите другой свободный интервал.";
  return null;
}

export function availableStarts(date: string, bookings: readonly Booking[], now = new Date()): number[] {
  return getSlots(date, bookings, now)
    .filter((slot) => !validateInterval(date, slot.start, slot.start + STUDIO.minimum, bookings, now))
    .map((slot) => slot.start);
}

export function defaultEnd(start: number): number { return start + STUDIO.minimum; }

export function availableEnds(date: string, start: number, bookings: readonly Booking[], now = new Date()): number[] {
  if (!Number.isFinite(start) || start < STUDIO.open || start > STUDIO.close - STUDIO.minimum) return [];
  const ends: number[] = [];
  for (let end = defaultEnd(start); end <= STUDIO.close; end += STUDIO.step) {
    if (validateInterval(date, start, end, bookings, now)) break;
    ends.push(end);
  }
  return ends;
}
