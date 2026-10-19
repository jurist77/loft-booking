import "server-only";
import { appMode } from "../lib/app-mode.ts";
import { timeLabel } from "../lib/availability.ts";
import { createBooking, getAvailability } from "./bookings.ts";
import { getDatabase } from "./database.ts";
import { ApiError, apiFailure, apiJson } from "./api-errors.ts";
import { availabilityInput, bookingInput, readJson } from "./api-input.ts";
import { apiSettings, checkOrigin, limitRequest } from "./api-security.ts";

export async function availabilityApi(request: Request) {
  try {
    if (appMode(process.env.APP_MODE) !== "server") throw new ApiError("NOT_FOUND");
    const settings = apiSettings(); limitRequest(request, settings, "GET");
    const { date, resourceId } = availabilityInput(request.url);
    return apiJson(getAvailability(getDatabase(), date, resourceId));
  } catch (error) { return apiFailure(error); }
}
export async function bookingsApi(request: Request) {
  try {
    if (appMode(process.env.APP_MODE) !== "server") throw new ApiError("NOT_FOUND");
    const settings = apiSettings(); limitRequest(request, settings, "POST"); checkOrigin(request, settings);
    const input = bookingInput(await readJson(request));
    const booking = createBooking(getDatabase(), input);
    if (booking.status === "cancelled") throw new ApiError("BOOKING_CANCELLED");
    return apiJson({ bookingId: booking.id, status: booking.status, date: input.date, start: timeLabel(input.start), end: timeLabel(input.end), resourceId: booking.resourceId }, 201);
  } catch (error) { return apiFailure(error); }
}
