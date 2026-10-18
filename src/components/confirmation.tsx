"use client";

import { useEffect, useRef } from "react";
import { durationLabel, formatDate, timeLabel } from "@/lib/availability";
import type { Confirmation as ConfirmationData } from "@/lib/booking-service";
import { ArrowIcon } from "./icons";

export function Confirmation({ value, onBack }: { value: ConfirmationData; onBack: () => void }) {
  const title = useRef<HTMLHeadingElement>(null);
  useEffect(() => { title.current?.focus(); title.current?.scrollIntoView({ behavior: "smooth", block: "center" }); }, []);
  return <section className="confirmation" aria-labelledby="confirmation-title">
    <span className="confirmation-check" aria-hidden="true">✓</span>
    <p className="eyebrow">Демонстрационное подтверждение</p>
    <h3 id="confirmation-title" tabIndex={-1} ref={title}>Всё готово для встречи.</h3>
    <p className="confirmation-lead">Вот как будет выглядеть ваше бронирование.</p>
    <dl className="confirmation-details">
      <div><dt>Дата</dt><dd>{formatDate(value.date, { day: "numeric", month: "long", year: "numeric" })}</dd></div>
      <div><dt>Время · Москва</dt><dd>{timeLabel(value.start)}–{timeLabel(value.end)}</dd></div>
      <div><dt>Продолжительность</dt><dd>{durationLabel(value.end - value.start)}</dd></div>
      <div><dt>Канал уведомления</dt><dd>{value.channel}</dd></div>
    </dl>
    <div className="demo-notice"><strong>Это демонстрация, а не реальная бронь.</strong><p>Бронирование фактически не сохранено. Студия не зарезервирована, уведомление не отправлено. Контактные данные не сохраняются.</p></div>
    <button className="button button-dark" type="button" onClick={onBack}>Вернуться к календарю <span aria-hidden="true"><ArrowIcon /></span></button>
  </section>;
}
