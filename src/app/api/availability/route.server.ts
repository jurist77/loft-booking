import { availabilityApi } from "@/server/booking-api";
export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export async function GET(request: Request) { return availabilityApi(request); }
