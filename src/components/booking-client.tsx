"use client";

import { useState, useSyncExternalStore } from "react";
import { Welcome } from "./welcome";
import { Booking } from "./booking";
import { createDemoBookings } from "@/lib/demo-bookings";

const subscribe = () => () => {};
const clientSnapshot = () => true;
const serverSnapshot = () => false;

function InitializedBooking() {
  // Created on the visitor's machine, not at static build time.
  const [initial] = useState(() => {
    const now = new Date();
    return { initialNow: now.toISOString(), initialBookings: createDemoBookings(now) };
  });
  return <Booking {...initial} />;
}

export function BookingClient() {
  const hydrated = useSyncExternalStore(subscribe, clientSnapshot, serverSnapshot);
  return hydrated ? <InitializedBooking /> : <><Welcome /><noscript>Для демонстрационного бронирования включите JavaScript в браузере.</noscript></>;
}
