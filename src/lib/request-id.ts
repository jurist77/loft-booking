/** RFC 4122 v4, 122 random bits. getRandomValues is also available on HTTP
 * testing origins where the secure-context-only randomUUID method is absent.
 * Never substitute Math.random, time or contact data for a cryptographic ID.
 */
export function createRequestId(): string {
  const source = globalThis.crypto;
  if (typeof source?.randomUUID === "function") return source.randomUUID();
  if (typeof source?.getRandomValues !== "function") throw new Error("SECURE_RANDOM_UNAVAILABLE");
  const bytes = source.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
