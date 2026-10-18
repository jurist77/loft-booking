import { createDemoBookings } from "./demo-bookings";
import { validateInterval, type Booking } from "./availability";
import { validateContact, type ContactInput } from "./validation";

export type BookingRequest = Booking & { contact: ContactInput };
export type Confirmation = Booking & { channel: string; demo: true };

/** Replace this boundary with a server API later; the UI never owns persistence. */
export interface BookingService {
  getBookings(now: Date): Promise<Booking[]>;
  confirm(request: BookingRequest, now: Date): Promise<Confirmation>;
}

export function createDemoService(readBookings: (now: Date) => Promise<Booking[]> = async (now) => createDemoBookings(now)): BookingService {
  return {
    getBookings: readBookings,
    async confirm(request, now) {
      const { errors } = validateContact(request.contact);
      if (Object.keys(errors).length) throw new Error("Проверьте контактные данные и согласие.");
      // Read again at confirmation; a future API must perform this check atomically.
      const fresh = await readBookings(now);
      const error = validateInterval(request.date, request.start, request.end, fresh, now);
      if (error) throw new Error(error);
      return { date: request.date, start: request.start, end: request.end, channel: request.contact.channel, demo: true };
    },
  };
}

export const demoBookingService = createDemoService();
