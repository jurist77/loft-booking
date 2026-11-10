import "server-only";
import type { StoredBooking } from "../bookings.ts";

const clean = (text: string | null) => (text ?? "").replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, " ").replace(/\s+/g, " ").trim();
function plural(n: number, one: string, few: string, many: string) { return n % 10 === 1 && n % 100 !== 11 ? one : n % 10 >= 2 && n % 10 <= 4 && !(n % 100 >= 12 && n % 100 <= 14) ? few : many; }
export function bookingMessage(booking: StoredBooking): string {
  const date = new Intl.DateTimeFormat("ru-RU", { timeZone: "Europe/Moscow", day: "2-digit", month: "2-digit", year: "numeric" });
  const time = new Intl.DateTimeFormat("ru-RU", { timeZone: "Europe/Moscow", hour: "2-digit", minute: "2-digit", hourCycle: "h23" });
  const minutes = (booking.endsAt - booking.startsAt) / 60000; const hours = Math.floor(minutes / 60); const rest = minutes % 60;
  const duration = [hours ? `${hours} ${plural(hours, "час", "часа", "часов")}` : "", rest ? `${rest} ${plural(rest, "минута", "минуты", "минут")}` : ""].filter(Boolean).join(" ");
  const phone = clean(booking.phone).replace(/^\+7(\d{3})(\d{3})(\d{2})(\d{2})$/, "+7 $1 $2-$3-$4");
  // Plain text: parse_mode is deliberately absent. HTML/Markdown in names is literal.
  return `✅ Новое бронирование — Studio 19.25\n\n📅 Дата: ${date.format(booking.startsAt)}\n🕒 Время: ${time.format(booking.startsAt)}–${time.format(booking.endsAt)}\n⏱ Продолжительность: ${duration}\n\n👤 Клиент: ${clean(booking.firstName)} ${clean(booking.lastName)}\n📱 Телефон: ${phone}`;
}
