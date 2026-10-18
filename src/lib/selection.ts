import { validateInterval, type Booking } from "./availability";
import { STUDIO } from "./studio";

export type RentalSelection = Pick<Booking, "start" | "end">;
export type SelectionChange = { selection: RentalSelection | null; error: string | null };

/** Clicks select one continuous, half-open interval. A clicked interior slot is included. */
export function selectSlot(
  date: string,
  slot: number,
  current: RentalSelection | null,
  bookings: readonly Booking[],
  now = new Date(),
): SelectionChange {
  if (!Number.isFinite(slot) || slot % STUDIO.step || slot < STUDIO.open || slot >= STUDIO.close) {
    return { selection: current, error: "Выберите получасовой интервал в рабочее время." };
  }
  if (current && slot === current.start) return { selection: null, error: null };

  let next: RentalSelection;
  if (!current) next = { start: slot, end: slot + STUDIO.minimum };
  else if (slot < current.start) next = { start: slot, end: current.end };
  else next = { start: current.start, end: slot + STUDIO.step };

  const error = validateInterval(date, next.start, next.end, bookings, now);
  return error ? { selection: current, error } : { selection: next, error: null };
}
