/** No invented number: missing or malformed configuration uses the placeholder. */
export function administratorContact(phone: string | null): { label: string; href: string } | null {
  const label = phone?.trim();
  if (!label) return null;
  const digits = label.replace(/[\s()-]/g, "");
  return /^\+?[1-9]\d{6,14}$/.test(digits) ? { label, href: `tel:${digits}` } : null;
}
