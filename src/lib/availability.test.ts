import { describe, expect, it } from "vitest";
import { addDays, addMonths, availableEnds, availableStarts, dateRange, defaultEnd, getSlots, isBookableDate, isCalendarDate, moscowDate, overlaps, validateInterval, type Booking } from "./availability";
import { createDemoBookings, DEMO_SCENARIOS } from "./demo-bookings";

const now = new Date("2026-10-18T03:00:00Z"); // 06:00 Moscow
const date = "2026-10-19";
const booking: Booking = { date, start: 18 * 60, end: 20 * 60 };

describe("Rental intervals", () => {
  it("rejects a 30-minute booking and accepts the minimum hour", () => {
    expect(validateInterval(date, 960, 990, [], now)).toMatch(/60 минут/);
    expect(validateInterval(date, 960, 1020, [], now)).toBeNull();
  });
  it("automatically ends an hour after 16:30", () => { expect(defaultEnd(990)).toBe(1050); });
  it("returns exactly 28 half-hour slots from 09:00 through 22:30", () => {
    const slots = getSlots(date, [booking], now);
    expect(slots).toHaveLength(28);
    expect(slots[0].start).toBe(540);
    expect(slots.at(-1)?.start).toBe(1350);
    expect(slots.filter((slot) => slot.busy).map((slot) => slot.start)).toEqual([1080, 1110, 1140, 1170]);
  });
  it("excludes busy starts and starts with fewer than two consecutive free slots", () => {
    const starts = availableStarts(date, [booking], now);
    expect(starts).not.toEqual(expect.arrayContaining([1050, 1080, 1110, 1140, 1170, 1350]));
    for (const invalid of [1050, 1080, 1110, 1140, 1170, 1350]) expect(starts).not.toContain(invalid);
    expect(starts).toContain(1020);
    expect(starts).toContain(1200);
  });
  it("only offers 17:00, 17:30, 18:00 for a 16:00 start before an 18:00 booking", () => {
    expect(availableEnds(date, 960, [booking], now)).toEqual([1020, 1050, 1080]);
  });
  it("does not offer times beyond a gap shorter than one hour", () => {
    const bookings = [{ date, start: 540, end: 600 }, { date, start: 630, end: 1380 }];
    expect(availableStarts(date, bookings, now)).toEqual([]);
  });
  it.each([[1050, 1110], [1080, 1200], [1020, 1230], [1110, 1170]])("rejects overlapping %i–%i", (start, end) => {
    expect(validateInterval(date, start, end, [booking], now)).toMatch(/занято/);
  });
  it("permits adjacent bookings on both sides", () => {
    expect(validateInterval(date, 1020, 1080, [booking], now)).toBeNull();
    expect(validateInterval(date, 1200, 1260, [booking], now)).toBeNull();
    expect(overlaps({ start: 960, end: 1020 }, { start: 1020, end: 1080 })).toBe(false);
  });
  it("ignores reservations on a different date", () => {
    expect(validateInterval("2026-10-20", 1080, 1200, [booking], now)).toBeNull();
  });
  it("allows a full free working day and the last hour", () => {
    expect(validateInterval(date, 540, 1380, [], now)).toBeNull();
    expect(availableEnds(date, 1320, [], now)).toEqual([1380]);
    expect(availableStarts(date, [], now).at(-1)).toBe(1320);
  });
  it("rejects times before opening and after closing", () => {
    expect(validateInterval(date, 510, 570, [], now)).toMatch(/09:00/);
    expect(validateInterval(date, 1320, 1410, [], now)).toMatch(/23:00/);
  });
  it.each([[421, 481], [NaN, 600], [600, Infinity], [600, 540]])("rejects invalid interval %i–%i", (start, end) => {
    expect(validateInterval(date, start, end, [], now)).not.toBeNull();
  });
  it("offers no time in a fully occupied day", () => {
    expect(availableStarts(date, [{ date, start: 540, end: 1380 }], now)).toEqual([]);
  });
});

describe("Moscow clock and calendar", () => {
  it("uses Moscow's calendar date across UTC midnight", () => {
    expect(moscowDate(new Date("2026-10-18T20:59:59Z"))).toBe("2026-10-18");
    expect(moscowDate(new Date("2026-10-18T21:00:00Z"))).toBe("2026-10-19");
  });
  it("rejects yesterday and allows today's future slots", () => {
    expect(isBookableDate("2026-10-17", now)).toBe(false);
    expect(validateInterval("2026-10-18", 540, 600, [], now)).toBeNull();
  });
  it("does not impose a lead-time restriction, but rejects even one elapsed second", () => {
    expect(validateInterval("2026-10-18", 600, 660, [], new Date("2026-10-18T07:00:00Z"))).toBeNull();
    expect(validateInterval("2026-10-18", 600, 660, [], new Date("2026-10-18T07:00:01Z"))).toMatch(/прошло/);
    expect(availableStarts("2026-10-18", [], new Date("2026-10-18T07:00:01Z"))[0]).toBe(630);
  });
  it("recognizes no remaining hours after closing in Moscow", () => {
    expect(availableStarts("2026-10-18", [], new Date("2026-10-18T20:01:00Z"))).toEqual([]);
  });
  it("uses a three-calendar-month horizon with inclusive last day", () => {
    expect(dateRange(now)).toEqual({ first: "2026-10-18", last: "2027-01-18" });
    expect(isBookableDate("2027-01-18", now)).toBe(true);
    expect(isBookableDate("2027-01-19", now)).toBe(false);
  });
  it("clamps the last day for shorter months, including leap years", () => {
    expect(addMonths("2026-01-31", 3)).toBe("2026-04-30");
    expect(addMonths("2028-01-31", 1)).toBe("2028-02-29");
    expect(addDays("2026-12-31", 1)).toBe("2027-01-01");
  });
  it.each(["2026-02-30", "not-a-date", "2026-13-01", "2026-10-19junk", "2026-1-2", ""])('rejects malformed date "%s"', (value) => {
    expect(isCalendarDate(value)).toBe(false);
    expect(validateInterval(value, 540, 600, [], now)).not.toBeNull();
  });
  it("creates all six fictional scenarios relative to today's Moscow date", () => {
    const data = createDemoBookings(now);
    expect(DEMO_SCENARIOS).toHaveLength(6);
    expect(data.filter((b) => b.date === "2026-10-18")).toHaveLength(0);
    expect(data.filter((b) => b.date === "2026-10-19")).toHaveLength(2);
    expect(data.filter((b) => b.date === "2026-10-20")).toHaveLength(3);
    expect(data.find((b) => b.date === "2026-10-21")?.start).toBe(540);
    expect(data.find((b) => b.date === "2026-10-22")?.end).toBe(1380);
    expect(availableStarts("2026-10-23", data, now)).toEqual([]);
    expect(availableStarts("2026-10-24", data, now)).toHaveLength(27);
  });
  it("keeps every demo booking inside the new 09:00–23:00 working day", () => {
    const data = createDemoBookings(now);
    expect(data.length).toBeGreaterThan(0);
    expect(data.every((booking) => booking.start >= 540 && booking.end <= 1380 && booking.start < booking.end)).toBe(true);
    expect(getSlots("2026-10-23", data, now).filter((slot) => slot.busy)).toHaveLength(28);
  });
});
