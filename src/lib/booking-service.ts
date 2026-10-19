import { createDemoBookings } from "./demo-bookings";
import { validateInterval, type Booking } from "./availability";
import { validateContact, type ContactDetails, type ContactInput, type NotificationChannel } from "./validation";

export type BookingRequest = Booking & { contact: ContactInput };
export type DemoConfirmation = Booking & { contact: ContactDetails; channel?: NotificationChannel; demo: true };
export type ServerConfirmation = Booking & { bookingId: string; resourceId: string; demo: false };
export type Confirmation = DemoConfirmation | ServerConfirmation;
type ClientErrorKind = "availability" | "overlap" | "input" | "limited" | "unknown" | "conflict";
export class BookingClientError extends Error {
  constructor(readonly kind: ClientErrorKind, message: string, readonly retryAt = 0, readonly uncertain = false) { super(message); this.name = "BookingClientError"; }
}

/** DEMO and same-origin HTTP adapters share this boundary; the UI never owns persistence. */
export interface BookingService<C extends Confirmation = Confirmation> {
  getBookings(now: Date, date?: string, signal?: AbortSignal): Promise<Booking[]>;
  confirm(request: BookingRequest, now: Date): Promise<C>;
  isRetry?(request: BookingRequest): boolean;
  acknowledgeChange?(): void;
  reset?(): void;
}

export function createDemoService(readBookings: (now: Date) => Promise<Booking[]> = async (now) => createDemoBookings(now)): BookingService<DemoConfirmation> {
  return {
    getBookings: readBookings,
    async confirm(request, now) {
      const { errors, phone } = validateContact(request.contact);
      if (Object.keys(errors).length) throw new Error("Проверьте контактные данные.");
      // Read again at confirmation; a future API must perform this check atomically.
      const fresh = await readBookings(now);
      const error = validateInterval(request.date, request.start, request.end, fresh, now);
      if (error) throw new Error(error);
      return {
        date: request.date, start: request.start, end: request.end, demo: true,
        contact: { firstName: request.contact.firstName.trim(), lastName: request.contact.lastName.trim(), phone: phone! },
        ...(request.contact.channel ? { channel: request.contact.channel as NotificationChannel } : {}),
      };
    },
  };
}

export const demoBookingService = createDemoService();
