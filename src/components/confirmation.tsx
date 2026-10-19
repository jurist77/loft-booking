"use client";

import { useEffect, useRef } from "react";
import { durationLabel, formatDate, timeLabel } from "@/lib/availability";
import type { Confirmation as ConfirmationData } from "@/lib/booking-service";
import { ArrowIcon } from "./icons";
import { AdminContact } from "./admin-contact";
import { STUDIO } from "@/lib/studio";
import { DEMO_WARNING } from "@/lib/demo";

export function Confirmation({ value, onBack }: { value: ConfirmationData; onBack: () => void }) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => { title.current?.focus({ preventScroll: true }); window.scrollTo({ top: 0, behavior: "instant" }); }, []);
  return <section className="confirmation" aria-labelledby="confirmation-title">
    <span className="confirmation-check" aria-hidden="true">✓</span>
    <p className="eyebrow">{STUDIO.name} · выбранное время</p>
    <h3 id="confirmation-title" data-step-heading tabIndex={-1} ref={title}>Ваше бронирование</h3>
    <dl className="confirmation-details">
      <div><dt>Дата аренды</dt><dd>{formatDate(value.date, { day: "numeric", month: "long", year: "numeric" })}</dd></div>
      <div><dt>Время аренды</dt><dd>{timeLabel(value.start)}–{timeLabel(value.end)}</dd></div>
      <div><dt>Продолжительность</dt><dd>{durationLabel(value.end - value.start)}</dd></div>
      {value.demo ? <><div><dt>Имя и фамилия</dt><dd>{value.contact.firstName} {value.contact.lastName}</dd></div>
      <div><dt>Контактный телефон</dt><dd data-testid="confirmation-phone">{value.contact.phone}</dd></div></> : <div><dt>Номер бронирования</dt><dd data-testid="booking-id"><code>{value.bookingId}</code></dd></div>}
    </dl>
    <div className="demo-notice">{value.demo ? <><strong>{DEMO_WARNING}</strong><p>Данные отображаются только в этой вкладке до нового бронирования или закрытия страницы.</p></> : <><strong>Бронирование подтверждено и сохранено.</strong><p>Уведомления пока не отправляются. Сохраните номер бронирования.</p></>}</div>
    <button className="button button-dark" type="button" onClick={onBack}>Новое бронирование <span aria-hidden="true"><ArrowIcon /></span></button>
    <AdminContact />
  </section>;
}
