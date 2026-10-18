"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { addDays, availableEnds, availableStarts, defaultEnd, durationLabel, formatDate, getSlots, moscowDate, timeLabel, validateInterval, type Booking as BookingData } from "@/lib/availability";
import { demoBookingService, type Confirmation as ConfirmationData } from "@/lib/booking-service";
import { DEMO_SCENARIOS, scenarioForDate } from "@/lib/demo-bookings";
import { validateContact, type ContactErrors, type ContactInput } from "@/lib/validation";
import { Calendar } from "./calendar";
import { ContactForm } from "./contact-form";
import { Confirmation } from "./confirmation";
import { ArrowIcon } from "./icons";

const EMPTY_CONTACT: ContactInput = { firstName: "", lastName: "", phone: "", eventType: "", channel: "", consent: false };

export function Booking({ initialNow, initialBookings }: { initialNow: string; initialBookings: BookingData[] }) {
  const [now, setNow] = useState(() => new Date(initialNow));
  const [date, setDate] = useState(() => moscowDate(new Date(initialNow)));
  const [month, setMonth] = useState(() => date.slice(0, 7));
  const [bookings, setBookings] = useState(initialBookings);
  const [start, setStart] = useState<number | "">("");
  const [end, setEnd] = useState<number | "">("");
  const [contact, setContact] = useState<ContactInput>(EMPTY_CONTACT);
  const [errors, setErrors] = useState<ContactErrors>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<ConfirmationData | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const today = moscowDate(now);

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 15000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    let active = true;
    demoBookingService.getBookings(new Date()).then((data) => { if (active) setBookings(data); }).catch(() => { if (active) setError("Не удалось загрузить доступность. Обновите страницу."); });
    return () => { active = false; };
  }, [today]);

  const slots = useMemo(() => getSlots(date, bookings, now), [date, bookings, now]);
  const starts = useMemo(() => availableStarts(date, bookings, now), [date, bookings, now]);
  const validStart = start !== "" && starts.includes(start) ? start : "";
  const ends = useMemo(() => validStart === "" ? [] : availableEnds(date, validStart, bookings, now), [date, validStart, bookings, now]);
  const validEnd = end !== "" && ends.includes(end) ? end : "";

  function selectDate(next: string) { setDate(next); setMonth(next.slice(0, 7)); setStart(""); setEnd(""); setError(""); }
  function selectStart(value: number | "") { setStart(value); setEnd(value === "" ? "" : defaultEnd(value)); setError(""); }

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const current = new Date();
    setNow(current);
    const checked = validateContact(contact);
    setErrors(checked.errors);
    const intervalError = validStart === "" || validEnd === "" ? "Выберите свободное время начала и окончания аренды." : validateInterval(date, validStart, validEnd, bookings, current);
    if (intervalError || Object.keys(checked.errors).length) {
      setError(intervalError || "Проверьте отмеченные поля формы.");
      if (Object.keys(checked.errors).length) requestAnimationFrame(() => formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      else requestAnimationFrame(() => errorRef.current?.focus());
      return;
    }
    setBusy(true); setError("");
    try {
      const value = await demoBookingService.confirm({ date, start: validStart as number, end: validEnd as number, contact: { ...contact, phone: checked.phone! } }, current);
      setConfirmation(value); setContact(EMPTY_CONTACT); setErrors({});
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Не удалось проверить интервал. Попробуйте ещё раз.");
      try { setBookings(await demoBookingService.getBookings(new Date())); } catch { /* Keep the previous snapshot and the visible error. */ }
      requestAnimationFrame(() => errorRef.current?.focus());
    } finally { setBusy(false); }
  }

  return <section id="booking" className="booking-section section-shell" aria-labelledby="booking-heading">
    <div className="section-heading booking-intro"><div><p className="eyebrow">Ваше время, ваше пространство</p><h2 id="booking-heading" ref={headingRef} tabIndex={-1}>Давайте запланируем<br /><em>что-то хорошее.</em></h2></div><p>Выберите удобный день и время.<br />Всё остальное начинается с вашей идеи.</p></div>
    {confirmation ? <Confirmation value={confirmation} onBack={() => { setConfirmation(null); selectDate(moscowDate(new Date())); setNow(new Date()); requestAnimationFrame(() => headingRef.current?.focus()); }} /> : <form className="booking-card" onSubmit={submit} noValidate ref={formRef}>
      <div className="date-time-panel">
        <div className="step-heading"><span className="step-number">01</span><h3>Когда встретимся?</h3><span className="timezone-badge">МСК · UTC+3</span></div>
        <Calendar month={month} selected={date} now={now} bookings={bookings} onMonth={setMonth} onSelect={selectDate} />
        <div className="time-section"><div className="time-heading"><h4>{formatDate(date, { day: "numeric", month: "long", weekday: "short" })}</h4><span className="availability-label">{scenarioForDate(date, now)}</span></div>
          <div className="slot-legend"><span><i className="legend-free" />Свободно</span><span><i className="legend-busy" />Занято</span><span><i className="legend-selected" />Ваше время</span></div>
          <div className="slots" role="group" aria-label="Все получасовые слоты">
            {slots.map((slot) => {
              const available = starts.includes(slot.start);
              const selected = validStart !== "" && validEnd !== "" && slot.start >= validStart && slot.start < validEnd;
              const status = slot.busy ? "занято" : slot.past ? "время прошло" : !available ? "недостаточно свободного времени для часа аренды" : "свободно";
              return <button type="button" className={`slot ${slot.busy ? "busy-slot" : ""} ${selected ? "selected-slot" : ""}`} key={slot.start} disabled={!available} aria-label={`${timeLabel(slot.start)} — ${status}`} aria-pressed={selected} title={`${timeLabel(slot.start)}–${timeLabel(slot.start + 30)}: ${status}`} onClick={() => selectStart(slot.start)}>{timeLabel(slot.start)}</button>;
            })}
          </div>
          <div className="field-pair time-selects"><label className="field" htmlFor="start">Начало<select id="start" value={validStart} onChange={(e) => selectStart(e.target.value === "" ? "" : Number(e.target.value))} required disabled={!starts.length}><option value="">{starts.length ? "Выберите время" : "Нет доступного времени"}</option>{starts.map((value) => <option key={value} value={value}>{timeLabel(value)}</option>)}</select></label>
            <label className="field" htmlFor="end">Окончание<select id="end" value={validEnd} onChange={(e) => setEnd(Number(e.target.value))} required disabled={validStart === ""}><option value="" disabled>Сначала начало</option>{ends.map((value) => <option key={value} value={value}>{timeLabel(value)}</option>)}</select></label></div>
          {!starts.length && <p className="empty-state" role="status">{slots.every((s) => s.busy) ? "Этот день полностью занят." : "На этот день не осталось свободного часа."} Выберите другую дату.</p>}
          <p className="field-hint">Минимум 1 час · шаг 30 минут · открыто 07:00–23:00</p>
        </div>
        <details className="demo-scenarios"><summary>Тестовые сценарии доступности</summary><p>Вымышленные бронирования для проверки прототипа:</p><div>{DEMO_SCENARIOS.map((scenario, offset) => <button type="button" key={scenario.label} onClick={() => selectDate(addDays(today, offset))}>{scenario.label}<span>{formatDate(addDays(today, offset))}</span></button>)}</div></details>
      </div>
      <div className="contact-panel"><div className="step-heading"><span className="step-number">02</span><h3>Немного о вас</h3></div><p className="contact-caption">Чтобы у вашей встречи появилось имя.<br />Все поля обязательны.</p>
        <ContactForm value={contact} errors={errors} onChange={setContact} />
        <div className="booking-summary" aria-live="polite"><span>{formatDate(date)}{validStart !== "" && validEnd !== "" ? ` · ${timeLabel(validStart)}–${timeLabel(validEnd)}` : " · время не выбрано"}</span><strong>{validStart !== "" && validEnd !== "" ? durationLabel(validEnd - validStart) : "От 1 часа"}</strong></div>
        {error && <div className="form-error" role="alert" ref={errorRef} tabIndex={-1}>{error}</div>}
        <button className="button button-dark submit-button" type="submit" disabled={busy}>{busy ? "Проверяем доступность…" : "Подтвердить выбор"}<span aria-hidden="true"><ArrowIcon /></span></button>
        <p className="demo-caption">Демонстрация · без оплаты и реального бронирования</p>
      </div>
    </form>}
  </section>;
}
