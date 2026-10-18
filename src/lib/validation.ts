export const EVENT_TYPES = ["День рождения", "Аренда студии", "Другое"] as const;
export const CHANNELS = ["Telegram", "SMS"] as const;

export type ContactInput = {
  firstName: string;
  lastName: string;
  phone: string;
  eventType: string;
  channel: string;
  consent: boolean;
};
export type ContactErrors = Partial<Record<keyof ContactInput, string>>;

export function normalizePhone(input: string): string | null {
  const clean = input.replace(/[\s()\-]/g, "");
  if (!/^\+?\d+$/.test(clean)) return null;
  let digits = clean.replace(/^\+/, "");
  if (digits.length === 10 && digits.startsWith("9") && !clean.startsWith("+")) digits = `7${digits}`;
  else if (digits.length === 11 && digits.startsWith("8") && !clean.startsWith("+")) digits = `7${digits.slice(1)}`;
  return /^79\d{9}$/.test(digits) ? `+${digits}` : null;
}

export function validateContact(input: ContactInput): { errors: ContactErrors; phone: string | null } {
  const errors: ContactErrors = {};
  for (const field of ["firstName", "lastName"] as const) {
    const value = input[field].trim();
    if (!value) errors[field] = field === "firstName" ? "Укажите имя." : "Укажите фамилию.";
    else if (value.length > 80 || !/^[\p{L}\p{M}][\p{L}\p{M}\s’'\-]*$/u.test(value)) errors[field] = "Используйте буквы, пробел или дефис, до 80 символов.";
  }
  const phone = normalizePhone(input.phone);
  if (!phone) errors.phone = "Введите российский мобильный номер, например +7 926 123-45-67.";
  if (!(EVENT_TYPES as readonly string[]).includes(input.eventType)) errors.eventType = "Выберите вид мероприятия.";
  if (!(CHANNELS as readonly string[]).includes(input.channel)) errors.channel = "Выберите канал уведомления.";
  if (!input.consent) errors.consent = "Для продолжения необходимо согласие.";
  return { errors, phone };
}
