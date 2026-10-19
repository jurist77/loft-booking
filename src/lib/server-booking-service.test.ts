import { afterEach, expect, it, vi } from "vitest";
import { createServerService } from "./server-booking-service";
import { BookingClientError } from "./booking-service";

const now = new Date("2026-10-19T08:00:00+03:00");
const request = { date: "2026-10-20", start: 600, end: 660, contact: { firstName: " Тест ", lastName: "Пример", phone: "8 (900) 000-00-00" } };
const id = "12345678-1234-4123-8123-123456789abc";
const nextId = "12345678-1234-4123-8123-123456789abd";
const payload = (init?: RequestInit) => JSON.parse(String(init?.body));
const success = (_url: unknown, init?: RequestInit) => {
  const body = payload(init);
  return Promise.resolve(Response.json({ bookingId: body.requestId, status: "confirmed", date: body.date, start: body.start, end: body.end, resourceId: body.resourceId }, { status: 201 }));
};
const failure = (status: number, code = "UNAVAILABLE", headers = {}) => Response.json({ error: { code, message: "private-path-and-contact-must-not-be-displayed" } }, { status, headers });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

it("loads only selected resource/date with no-store, same-origin and no contact data", async () => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ date: request.date, resourceId: "test-room", timezone: "Europe/Moscow", busy: [{ start: "12:00", end: "14:00" }] }));
  const result = await createServerService({ resourceId: "test-room", basePath: "/studio", fetcher }).getBookings(now, request.date);
  expect(result).toEqual([{ date: request.date, start: 720, end: 840 }]);
  expect(fetcher.mock.calls[0][0]).toBe("/studio/api/availability?date=2026-10-20&resourceId=test-room");
  expect(fetcher.mock.calls[0][1]).toMatchObject({ cache: "no-store", mode: "same-origin", credentials: "same-origin", method: "GET" });
  expect(fetcher.mock.calls[0][1]).not.toHaveProperty("body");
});
it.each([failure(503), Response.json({ busy: [] }), Response.json({ date: request.date, resourceId: "studio-19-25", timezone: "Europe/Moscow", busy: [{ start: "bad", end: "14:00" }] })])("never treats an unavailable/malformed response as a free day", async (response) => {
  const service = createServerService({ fetcher: vi.fn<typeof fetch>().mockResolvedValue(response) });
  await expect(service.getBookings(now, request.date)).rejects.toMatchObject({ kind: "availability" });
});
it("normalizes contacts, returns only confirmed public details and reuses the ID", async () => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(success); const uuid = vi.fn(() => id);
  const service = createServerService({ fetcher, uuid });
  expect(await service.confirm(request, now)).toEqual({ date: request.date, start: 600, end: 660, bookingId: id, resourceId: "studio-19-25", demo: false });
  await service.confirm({ ...request, contact: { firstName: "Тест", lastName: "Пример", phone: "+79000000000" } }, now);
  expect(uuid).toHaveBeenCalledTimes(1);
  expect(payload(fetcher.mock.calls[0][1])).toMatchObject({ requestId: id, firstName: "Тест", phone: "+79000000000" });
  expect(payload(fetcher.mock.calls[1][1]).requestId).toBe(id);
});
it("preserves a request after a network failure and retries without making automatic requests", async () => {
  const fetcher = vi.fn<typeof fetch>().mockRejectedValueOnce(new Error("private contact")); fetcher.mockImplementationOnce(success);
  const uuid = vi.fn(() => id); const service = createServerService({ fetcher, uuid });
  await expect(service.confirm(request, now)).rejects.toMatchObject({ kind: "unknown", uncertain: true });
  expect(fetcher).toHaveBeenCalledTimes(1); expect(service.isRetry?.(request)).toBe(true);
  await service.confirm(request, now);
  expect(uuid).toHaveBeenCalledTimes(1); expect(fetcher.mock.calls.map(([, init]) => payload(init).requestId)).toEqual([id, id]);
});
it("requires acknowledged changes after an unknown outcome, and keeps the old ID for unchanged data", async () => {
  const fetcher = vi.fn<typeof fetch>().mockRejectedValueOnce(new Error()); fetcher.mockImplementation(success);
  const uuid = vi.fn().mockReturnValueOnce(id).mockReturnValue(nextId); const service = createServerService({ fetcher, uuid });
  await expect(service.confirm(request, now)).rejects.toBeInstanceOf(BookingClientError);
  const changed = { ...request, end: 690 };
  await expect(service.confirm(changed, now)).rejects.toMatchObject({ uncertain: true }); expect(fetcher).toHaveBeenCalledTimes(1);
  service.acknowledgeChange?.(); expect(service.isRetry?.(request)).toBe(true);
  await service.confirm(changed, now); expect(payload(fetcher.mock.calls[1][1]).requestId).toBe(nextId);
});
it("changes UUID only for changed canonical data or an explicit new-booking reset", async () => {
  const fetcher = vi.fn<typeof fetch>().mockImplementation(success); const uuid = vi.fn().mockReturnValueOnce(id).mockReturnValue(nextId);
  const service = createServerService({ fetcher, uuid });
  await service.confirm(request, now); service.reset?.(); await service.confirm(request, now);
  expect(uuid).toHaveBeenCalledTimes(2); expect(payload(fetcher.mock.calls[1][1]).requestId).toBe(nextId);
});
it("ignores raw server messages and distinguishes overlap, input and ID conflicts", async () => {
  for (const [status, code, kind] of [[409, "BOOKING_OVERLAP", "overlap"], [409, "BOOKING_ID_CONFLICT", "conflict"], [409, "BOOKING_CANCELLED", "conflict"], [400, "INVALID_CONTACT", "input"]] as const) {
    const service = createServerService({ fetcher: vi.fn<typeof fetch>().mockResolvedValue(failure(status, code)), uuid: () => id });
    try { await service.confirm(request, now); throw new Error("must reject"); }
    catch (error) { expect(error).toMatchObject({ kind }); expect((error as Error).message).not.toContain("private"); }
  }
});
it.each([{ bookingId: "wrong" }, { status: "cancelled" }, { date: "2026-10-21" }, { end: "12:00" }])("requires a matching committed response: %j", async (change) => {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(Response.json({ bookingId: id, status: "confirmed", date: request.date, start: "10:00", end: "11:00", resourceId: "studio-19-25", ...change }, { status: 201 }));
  await expect(createServerService({ fetcher, uuid: () => id }).confirm(request, now)).rejects.toMatchObject({ uncertain: true });
});
it("honors Retry-After locally, retains uncertainty, and never regenerates the request ID", async () => {
  vi.useFakeTimers(); vi.setSystemTime(now);
  const fetcher = vi.fn<typeof fetch>().mockRejectedValueOnce(new Error()).mockResolvedValueOnce(failure(429, "RATE_LIMITED", { "Retry-After": "2" })).mockImplementation(success);
  const uuid = vi.fn(() => id); const service = createServerService({ fetcher, uuid });
  await expect(service.confirm(request, now)).rejects.toMatchObject({ kind: "unknown" });
  await expect(service.confirm(request, now)).rejects.toMatchObject({ kind: "limited", uncertain: true });
  await expect(service.confirm(request, now)).rejects.toMatchObject({ kind: "limited" }); expect(fetcher).toHaveBeenCalledTimes(2);
  await vi.advanceTimersByTimeAsync(2001); await service.confirm(request, now); expect(uuid).toHaveBeenCalledTimes(1);
});
it("honors an HTTP-date Retry-After for availability instead of querying repeatedly", async () => {
  vi.useFakeTimers(); vi.setSystemTime(now);
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(failure(429, "RATE_LIMITED", { "Retry-After": new Date(now.getTime() + 5000).toUTCString() }));
  const service = createServerService({ fetcher });
  await expect(service.getBookings(now, request.date)).rejects.toMatchObject({ kind: "limited", retryAt: now.getTime() + 5000 });
  await expect(service.getBookings(now, request.date)).rejects.toMatchObject({ kind: "limited" }); expect(fetcher).toHaveBeenCalledTimes(1);
});
it("aborts on a real client deadline and preserves the same attempt for retry", async () => {
  vi.useFakeTimers();
  const fetcher = vi.fn<typeof fetch>().mockImplementationOnce(async (_url, init) => new Promise((_resolve, reject) => init!.signal!.addEventListener("abort", () => reject(new Error("timeout"))))).mockImplementation(success);
  const uuid = vi.fn(() => id); const service = createServerService({ fetcher, uuid, timeoutMs: 50 });
  const result = expect(service.confirm(request, now)).rejects.toMatchObject({ uncertain: true });
  await vi.advanceTimersByTimeAsync(51); await result; await service.confirm(request, now); expect(uuid).toHaveBeenCalledTimes(1);
});
it("refuses a simultaneous second send without issuing another HTTP request", async () => {
  let finish!: (response: Response) => void;
  const fetcher = vi.fn<typeof fetch>().mockImplementation((_url, init) => new Promise((resolve) => { finish = async (response) => resolve(response); expect(payload(init).requestId).toBe(id); }));
  const service = createServerService({ fetcher, uuid: () => id }); const first = service.confirm(request, now);
  await expect(service.confirm(request, now)).rejects.toMatchObject({ kind: "unknown" }); expect(fetcher).toHaveBeenCalledTimes(1);
  finish(await success("", fetcher.mock.calls[0][1])); await first;
});
