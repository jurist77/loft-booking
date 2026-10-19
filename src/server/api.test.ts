import { expect, it } from "vitest";
import { apiSettings, ApiLimiter, checkOrigin, clientKey } from "./api-security";
import { availabilityInput, bookingInput, readJson } from "./api-input";

const origin = "https://studio.example";
const settings = apiSettings({ API_PUBLIC_ORIGIN: origin });
const fixture = { requestId: "12345678-1234-4123-8123-123456789abc", resourceId: "studio-19-25", date: "2030-01-15", start: "09:00", end: "10:00", firstName: "Тест", lastName: "Пример", phone: "+79000000000" };
const request = (body: string | Uint8Array, headers = {}) => new Request(origin, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: body as BodyInit });

it.each(["http://studio.example", "https://studio.example/", "https://user:pass@studio.example", "https://studio.example/path", "null"])("fails closed for an invalid public Origin config: %s", (value) => {
  expect(() => apiSettings({ API_PUBLIC_ORIGIN: value })).toThrow("API_UNAVAILABLE");
});
it("does not trust Host or forwarding headers for Origin or client identity", () => {
  const req = new Request(origin, { headers: { origin: "https://attacker.example", host: "attacker.example", "x-forwarded-host": "attacker.example", "x-forwarded-for": "192.0.2.1", "x-studio-client-ip": "192.0.2.2" } });
  expect(() => checkOrigin(req, settings)).toThrow("ORIGIN_NOT_ALLOWED"); expect(clientKey(req, settings)).toBe("shared");
  expect(() => checkOrigin(new Request(origin, { headers: { origin, "sec-fetch-site": "cross-site" } }), settings)).toThrow("ORIGIN_NOT_ALLOWED");
  expect(() => checkOrigin(new Request(origin), settings)).toThrow("ORIGIN_NOT_ALLOWED");
});
it("trusts only an explicit proxy mode and canonicalizes validated IPv6", () => {
  const trusted = apiSettings({ API_TRUST_PROXY: "true", API_PUBLIC_ORIGIN: origin });
  const req = (ip: string) => new Request(origin, { headers: { "x-studio-client-ip": ip } });
  expect(clientKey(req("2001:db8:0:0:0:0:0:1"), trusted)).toBe(clientKey(req("2001:db8::1"), trusted));
  for (const ip of ["", "unknown", "192.0.2.1, 192.0.2.2", "192.0.2.1:80", "fe80::1%eth0"]) expect(() => clientKey(req(ip), trusted)).toThrow("API_UNAVAILABLE");
  expect(() => apiSettings({ API_TRUST_PROXY: "yes" })).toThrow("API_UNAVAILABLE");
});
it("limits clients and aggregate traffic with bounded windows and an actual reset", () => {
  const limiter = new ApiLimiter();
  for (let i = 0; i < 10; i++) limiter.check("POST", "one", 0);
  expect(() => limiter.check("POST", "one", 59999)).toThrow("RATE_LIMITED");
  for (let i = 0; i < 50; i++) limiter.check("POST", `client-${i}`, 0);
  expect(() => limiter.check("POST", "another", 1)).toThrow("RATE_LIMITED");
  expect(() => limiter.check("GET", "one", 1)).not.toThrow();
  expect(() => limiter.check("POST", "one", 60000)).not.toThrow();
});
it("accepts flat JSON and normalizes the transport UUID without changing business rules", async () => {
  const body = await readJson(request(JSON.stringify(fixture)));
  expect(bookingInput(body)).toMatchObject({ id: fixture.requestId, start: 540, end: 600 });
  expect(bookingInput({ ...fixture, requestId: fixture.requestId.toUpperCase() }).id).toBe(fixture.requestId);
  expect(() => bookingInput({ ...fixture, admin: true })).toThrow("INVALID_INPUT");
  expect(() => bookingInput({ ...fixture, firstName: "a".repeat(81) })).toThrow("INVALID_INPUT");
  expect(() => bookingInput({ ...fixture, phone: "1".repeat(33) })).toThrow("INVALID_INPUT");
  expect(() => bookingInput({ ...fixture, requestId: "not-a-uuid" })).toThrow("INVALID_INPUT");
  expect(() => bookingInput({ ...fixture, date: "2030-02-30" })).toThrow("INVALID_DATE");
  expect(() => bookingInput({ ...fixture, start: "9:00" })).toThrow("INVALID_TIME");
});
it.each(["[]", "null", "{}", '{"a":1}', '{"a":"x",}', '{"a":"x","a":"y"}', '{"phone":"x","ph\\u006fne":"y"}', '{"a":{},"a":"x"}'])("rejects malformed, non-string or duplicate JSON: %s", async (body) => {
  await expect(readJson(request(body))).rejects.toBeDefined();
});
it("bounds actual bytes independently of Content-Length, rejects bad UTF-8 and encodings", async () => {
  await expect(readJson(request("x".repeat(4097)))).rejects.toMatchObject({ code: "BODY_TOO_LARGE" });
  await expect(readJson(request("{}", { "content-length": "4097" }))).rejects.toMatchObject({ code: "BODY_TOO_LARGE" });
  await expect(readJson(request(new Uint8Array([0xc3, 0x28])))).rejects.toMatchObject({ code: "INVALID_JSON" });
  await expect(readJson(request("{}", { "content-type": "text/plain" }))).rejects.toMatchObject({ code: "UNSUPPORTED_MEDIA_TYPE" });
  await expect(readJson(request("{}", { "content-encoding": "gzip" }))).rejects.toMatchObject({ code: "UNSUPPORTED_MEDIA_TYPE" });
});
it("rejects ambiguous or excessive URL parameters without SQL interpolation", () => {
  expect(availabilityInput(`${origin}?date=2030-01-15`)).toEqual({ date: "2030-01-15", resourceId: "studio-19-25" });
  for (const suffix of ["?date=2030-01-15&date=2030-01-16", "?date=2030-01-15&admin=true", "?date=2030-01-15&resourceId=", "?date=2030-01-15&resourceId=" + "x".repeat(129)]) expect(() => availabilityInput(origin + suffix)).toThrow("INVALID_INPUT");
  expect(() => availabilityInput(`${origin}?date=2030-02-30`)).toThrow("INVALID_DATE");
});
