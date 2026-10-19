import { bookingsApi } from "@/server/booking-api";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function POST(request: Request) { return bookingsApi(request); }
