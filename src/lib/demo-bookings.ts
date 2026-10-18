import { STUDIO } from "./studio";
import { addDays, moscowDate, type Booking } from "./availability";

export const DEMO_SCENARIOS = [
  { label: "Свободный день", intervals: [] },
  { label: "Частично занят", intervals: [[12 * 60, 14 * 60], [18 * 60, 20 * 60]] },
  { label: "Бронирования подряд", intervals: [[10 * 60, 12 * 60], [12 * 60, 14 * 60], [14 * 60, 16 * 60]] },
  { label: "Занято утро", intervals: [[STUDIO.open, 12 * 60]] },
  { label: "Занят вечер", intervals: [[17 * 60, STUDIO.close]] },
  { label: "Полностью занят", intervals: [[STUDIO.open, STUDIO.close]] },
] as const;

/** Six fictional scenarios repeat across the horizon, anchored to Moscow today. */
export function createDemoBookings(now = new Date()): Booking[] {
  const today = moscowDate(now);
  return Array.from({ length: 100 }, (_, offset) => {
    const date = addDays(today, offset);
    return DEMO_SCENARIOS[offset % DEMO_SCENARIOS.length].intervals.map(([start, end]) => ({ date, start, end }));
  }).flat();
}

export function scenarioForDate(date: string, now = new Date()): string {
  const days = Math.round((Date.parse(`${date}T12:00:00Z`) - Date.parse(`${moscowDate(now)}T12:00:00Z`)) / 86400000);
  return DEMO_SCENARIOS[((days % 6) + 6) % 6].label;
}
