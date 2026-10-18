import { createDemoBookings } from "./demo-bookings";
import { validateInterval, type Booking } from "./availability";
import { validateContact, type ContactDetails, type ContactInput, type NotificationChannel } from "./validation";

export type BookingRequest = Booking & { contact: ContactInput };
export type Confirmation = Booking & { contact: ContactDetails; channel?: NotificationChannel; demo: true };

/** Replace this boundary with a server API later; the UI never owns persistence. */
export interface BookingService {
  getBookings(now: Date): Promise<Booking[]>;
  confirm(request: BookingRequest, now: Date): Promise<Confirmation>;
}

export function createDemoService(readBookings: (now: Date) => Promise<Booking[]> = async (now) => createDemoBookings(now)): BookingService {
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
