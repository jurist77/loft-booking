import { describe, expect, it } from "vitest";
import { selectSlot, type RentalSelection } from "./selection";
import type { Booking } from "./availability";

const date = "2026-10-19";
const now = new Date("2026-10-18T03:00:00Z");
const hour = { start: 600, end: 660 };
const choose = (slot: number, current: RentalSelection | null = null, bookings: Booking[] = []) => selectSlot(date, slot, current, bookings, now);

describe("Continuous selection in the time grid", () => {
  it("selects exactly one hour on the first click", () => { expect(choose(600)).toEqual({ selection: hour, error: null }); });
  it("extends one slot to the right", () => { expect(choose(660, hour).selection).toEqual({ start: 600, end: 690 }); });
  it("extends to the left", () => { expect(choose(570, hour).selection).toEqual({ start: 570, end: 660 }); });
  it("includes intermediate free slots when extending to the right", () => { expect(choose(720, hour).selection).toEqual({ start: 600, end: 750 }); });
  it("includes intermediate free slots when extending to the left", () => { expect(choose(540, hour).selection).toEqual({ start: 540, end: 660 }); });
  it("does not cross an occupied interval on the right", () => {
    const result = choose(750, hour, [{ date, start: 690, end: 720 }]);
    expect(result.selection).toEqual(hour); expect(result.error).toMatch(/занято/);
  });
  it("does not cross an occupied interval on the left", () => {
    const result = choose(540, hour, [{ date, start: 570, end: 600 }]);
    expect(result.selection).toEqual(hour); expect(result.error).toMatch(/занято/);
  });
  it("cannot start without a whole free hour", () => {
    expect(choose(600, null, [{ date, start: 630, end: 690 }]).selection).toBeNull();
  });
  it("shortens to include the clicked selected slot", () => {
    expect(choose(660, { start: 600, end: 780 }).selection).toEqual({ start: 600, end: 690 });
  });
  it("can shorten to exactly one hour", () => {
    expect(choose(630, { start: 600, end: 780 }).selection).toEqual(hour);
  });
  it("does not shorten the minimum hour by clicking its second slot", () => { expect(choose(630, hour).selection).toEqual(hour); });
  it("clicking the first selected slot resets the interval", () => { expect(choose(600, hour)).toEqual({ selection: null, error: null }); });
  it("clicking the last selected slot is an unambiguous no-op", () => {
    expect(choose(720, { start: 600, end: 750 }).selection).toEqual({ start: 600, end: 750 });
  });
  it("cannot start at 22:30, but can extend to include it and finish at 23:00", () => {
    expect(choose(1320).selection).toEqual({ start: 1320, end: 1380 });
    expect(choose(1350).selection).toBeNull();
    expect(choose(1350, { start: 1260, end: 1320 }).selection).toEqual({ start: 1260, end: 1380 });
  });
  it.each([390, 510, 1380, 1410, 601, NaN, Infinity])("rejects invalid slot %s without changing selection", (slot) => {
    const result = choose(slot, hour); expect(result.selection).toEqual(hour); expect(result.error).not.toBeNull();
  });
  it("permits booking up to an adjacent occupied boundary", () => {
    expect(choose(690, hour, [{ date, start: 720, end: 780 }]).selection).toEqual({ start: 600, end: 720 });
  });
  it("rejects elapsed time in Moscow, including extending into the past", () => {
    const current = new Date("2026-10-19T07:00:01Z");
    expect(selectSlot(date, 600, null, [], current).error).toMatch(/прошло/);
    const selection = { start: 660, end: 720 };
    expect(selectSlot(date, 600, selection, [], current).selection).toEqual(selection);
  });
  it("does not permit dates outside the existing booking horizon", () => {
    expect(selectSlot("2027-01-19", 600, null, [], now).selection).toBeNull();
  });
});
