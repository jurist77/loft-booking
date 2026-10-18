import { describe, expect, it, vi } from "vitest";
import { createDemoService } from "./booking-service";
import type { Booking } from "./availability";
import type { ContactInput } from "./validation";

const now = new Date("2026-10-18T03:00:00Z");
const contact: ContactInput = { firstName: "Анна", lastName: "Иванова", phone: "89261234567", eventType: "Другое", channel: "SMS", consent: true };
const request = { date: "2026-10-19", start: 960, end: 1020, contact };

describe("Demo booking service", () => {
  it("rechecks fresh availability and rejects a conflict introduced after loading", async () => {
    const read = vi.fn<(now: Date) => Promise<Booking[]>>()
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce([{ date: request.date, start: 990, end: 1080 }]);
    const service = createDemoService(read);
    expect(await service.getBookings(now)).toEqual([]);
    await expect(service.confirm(request, now)).rejects.toThrow(/занято/);
    expect(read).toHaveBeenCalledTimes(2);
  });
  it("returns demo details without contact information or persistence", async () => {
    const service = createDemoService(async () => []);
    expect(await service.confirm(request, now)).toEqual({ date: request.date, start: 960, end: 1020, channel: "SMS", demo: true });
    expect(await service.getBookings(now)).toEqual([]);
    await expect(service.confirm(request, now)).resolves.toHaveProperty("demo", true);
  });
  it("rejects invalid contact data even for a free interval", async () => {
    await expect(createDemoService(async () => []).confirm({ ...request, contact: { ...contact, consent: false } }, now)).rejects.toThrow(/контактные/);
  });
  it("checks elapsed time again on confirmation", async () => {
    await expect(createDemoService(async () => []).confirm(request, new Date("2026-10-19T13:00:01Z"))).rejects.toThrow(/прошло/);
  });
});
