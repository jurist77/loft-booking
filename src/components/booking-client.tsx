"use client";

import { useState, useSyncExternalStore } from "react";
import { Welcome } from "./welcome";
import { Booking } from "./booking";
import { createDemoBookings } from "@/lib/demo-bookings";
import { DEPLOYMENT } from "@/lib/deployment";
import { createServerService } from "@/lib/server-booking-service";
import { demoBookingService } from "@/lib/booking-service";

const subscribe = () => () => {};
const clientSnapshot = () => true;
const serverSnapshot = () => false;

function InitializedBooking() {
  // Created on the visitor's machine, not at static build time.
  const [initial] = useState(() => {
    const now = new Date();
    return { initialNow: now.toISOString(), initialBookings: DEPLOYMENT.mode === "demo" ? createDemoBookings(now) : [] };
  });
  // Direct build constant lets the DEMO bundle omit the real HTTP transport entirely.
  const [service] = useState(() => process.env.NEXT_PUBLIC_APP_MODE === "server" ? createServerService() : demoBookingService);
  return <Booking {...initial} service={service} server={DEPLOYMENT.mode === "server"} />;
}

export function BookingClient() {
  const hydrated = useSyncExternalStore(subscribe, clientSnapshot, serverSnapshot);
  return hydrated ? <InitializedBooking /> : <><Welcome /><noscript>Для демонстрационного бронирования включите JavaScript в браузере.</noscript></>;
}
