"use client";

import { useEffect, useRef } from "react";
import { durationLabel, formatDate, timeLabel } from "@/lib/availability";
import type { Confirmation as ConfirmationData } from "@/lib/booking-service";
import { ArrowIcon } from "./icons";
import { AdminContact } from "./admin-contact";
import { DEMO_WARNING } from "@/lib/demo";

export function Confirmation({ value, onBack }: { value: ConfirmationData; onBack: () => void }) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => { title.current?.focus(); title.current?.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "center" }); }, []);
  return <section className="confirmation" aria-labelledby="confirmation-title">
    <span className="confirmation-check" aria-hidden="true">✓</span>
    <p className="eyebrow">Loft Studio · выбранное время</p>
    <h3 id="confirmation-title" tabIndex={-1} ref={title}>Ваше бронирование</h3>
    <dl className="confirmation-details">
      <div><dt>Дата аренды</dt><dd>{formatDate(value.date, { day: "numeric", month: "long", year: "numeric" })}</dd></div>
      <div><dt>Время аренды</dt><dd>{timeLabel(value.start)}–{timeLabel(value.end)}</dd></div>
      <div><dt>Продолжительность</dt><dd>{durationLabel(value.end - value.start)}</dd></div>
      <div><dt>Имя и фамилия</dt><dd>{value.contact.firstName} {value.contact.lastName}</dd></div>
      <div><dt>Контактный телефон</dt><dd data-testid="confirmation-phone">{value.contact.phone}</dd></div>
      <div><dt>Тип мероприятия</dt><dd>{value.contact.eventType}</dd></div>
    </dl>
    <div className="demo-notice"><strong>{DEMO_WARNING}</strong><p>Данные отображаются только в этой вкладке до нового бронирования или закрытия страницы.</p></div>
    <button className="button button-dark" type="button" onClick={onBack}>Новое бронирование <span aria-hidden="true"><ArrowIcon /></span></button>
    <AdminContact />
  </section>;
}
