import { afterEach, expect, it, vi } from "vitest";
import { webcrypto } from "node:crypto";
import { createRequestId } from "./request-id";

afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });
const uuidV4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

it("uses native randomUUID when available", () => {
  const native = vi.fn(() => "12345678-1234-4123-8123-123456789abc");
  const fallback = vi.fn(); vi.stubGlobal("crypto", { randomUUID: native, getRandomValues: fallback });
  expect(createRequestId()).toBe(native.mock.results[0].value);
  expect(native).toHaveBeenCalledTimes(1); expect(fallback).not.toHaveBeenCalled();
});
it("formats CSPRNG bytes as UUID v4 without randomUUID or Math.random", () => {
  const fill = vi.fn((bytes: Uint8Array) => { bytes.set(Array.from({ length: 16 }, (_, index) => index)); return bytes; });
  vi.stubGlobal("crypto", { getRandomValues: fill }); vi.spyOn(Math, "random").mockImplementation(() => { throw new Error("weak random forbidden"); });
  expect(createRequestId()).toBe("00010203-0405-4607-8809-0a0b0c0d0e0f");
  expect(fill).toHaveBeenCalledTimes(1); expect(fill.mock.calls[0][0]).toHaveLength(16);
});
it("produces distinct cryptographic UUIDs in the HTTP-origin capability set", () => {
  vi.stubGlobal("crypto", { getRandomValues: webcrypto.getRandomValues.bind(webcrypto) });
  const values = Array.from({ length: 100 }, createRequestId);
  expect(new Set(values).size).toBe(100); for (const id of values) expect(id).toMatch(uuidV4);
});
it("fails closed if cryptographic randomness is absent", () => {
  vi.stubGlobal("crypto", undefined);
  expect(createRequestId).toThrow("SECURE_RANDOM_UNAVAILABLE");
});
