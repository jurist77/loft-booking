"use client";

import { useEffect, useRef, useState } from "react";
import { durationLabel, formatDate, moscowDate, timeLabel, validateInterval, type Booking as BookingData } from "@/lib/availability";
import { demoBookingService, type Confirmation as ConfirmationData } from "@/lib/booking-service";
import { selectSlot, type RentalSelection } from "@/lib/selection";
import { validateContact, type ContactErrors, type ContactInput } from "@/lib/validation";
import { Calendar } from "./calendar";
import { ContactForm } from "./contact-form";
import { Confirmation } from "./confirmation";
import { TimeGrid } from "./time-grid";
import { ArrowIcon } from "./icons";
import { AdminContact } from "./admin-contact";
import { Welcome } from "./welcome";
import { DEMO_WARNING } from "@/lib/demo";

const EMPTY_CONTACT: ContactInput = { firstName: "", lastName: "", phone: "", eventType: "" };

export function Booking({ initialNow, initialBookings }: { initialNow: string; initialBookings: BookingData[] }) {
  const [now, setNow] = useState(() => new Date(initialNow));
  const [date, setDate] = useState(() => moscowDate(new Date(initialNow)));
  const [month, setMonth] = useState(() => date.slice(0, 7));
  const [bookings, setBookings] = useState(initialBookings);
  const [selection, setSelection] = useState<RentalSelection | null>(null);
  const [step, setStep] = useState<"welcome" | "calendar" | "time" | "contact" | "confirmation">("welcome");
  const [contact, setContact] = useState<ContactInput>(EMPTY_CONTACT);
  const [errors, setErrors] = useState<ContactErrors>({});
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmation, setConfirmation] = useState<ConfirmationData | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const today = moscowDate(now);
  const validSelection = selection && !validateInterval(date, selection.start, selection.end, bookings, now) ? selection : null;

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 15000);
    return () => clearInterval(timer);
  }, []);
  useEffect(() => {
    let active = true;
    demoBookingService.getBookings(new Date()).then((data) => { if (active) setBookings(data); }).catch(() => { if (active) setError("Не удалось загрузить доступность. Обновите страницу."); });
    return () => { active = false; };
  }, [today]);

  function goTo(next: typeof step) {
    setStep(next);
    requestAnimationFrame(() => {
      document.querySelector<HTMLElement>("[data-step-heading]")?.focus({ preventScroll: true });
      window.scrollTo({ top: 0, behavior: "instant" });
    });
  }
  function selectDate(next: string) {
    if (next !== date) {
      setDate(next); setMonth(next.slice(0, 7)); setSelection(null); setError("");
    }
    goTo("time");
  }
  function chooseSlot(slot: number) {
    const current = new Date();
    const previous = selection && !validateInterval(date, selection.start, selection.end, bookings, current) ? selection : null;
    const change = selectSlot(date, slot, previous, bookings, current);
    setNow(current); setSelection(change.selection); setError(change.error || "");
  }
  function continueToContact() {
    const current = new Date();
    const problem = selection ? validateInterval(date, selection.start, selection.end, bookings, current) : "Выберите время аренды.";
    setNow(current);
    if (problem) { setError(problem); return; }
    setError(""); goTo("contact");
  }
  function newBooking() {
    const current = new Date(); const next = moscowDate(current);
    setConfirmation(null); setContact(EMPTY_CONTACT); setErrors({}); setSelection(null);
    setDate(next); setMonth(next.slice(0, 7)); setNow(current); setError(""); goTo("welcome");
  }
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy) return;
    const current = new Date();
    setNow(current);
    const checked = validateContact(contact);
    setErrors(checked.errors);
    const intervalError = selection ? validateInterval(date, selection.start, selection.end, bookings, current) : "Вернитесь к календарю и выберите время.";
    if (intervalError || Object.keys(checked.errors).length) {
      setError(intervalError || "Проверьте отмеченные поля формы.");
      requestAnimationFrame(() => {
        if (Object.keys(checked.errors).length) formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
        else errorRef.current?.focus();
      });
      return;
    }
    setBusy(true); setError("");
    try {
      const value = await demoBookingService.confirm({ date, ...selection!, contact: { ...contact, phone: checked.phone! } }, current);
      setConfirmation(value); setContact(EMPTY_CONTACT); setErrors({}); goTo("confirmation");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Не удалось проверить интервал. Попробуйте ещё раз.");
      try { setBookings(await demoBookingService.getBookings(new Date())); } catch { /* Preserve the visible error and the last snapshot. */ }
      requestAnimationFrame(() => errorRef.current?.focus());
    } finally { setBusy(false); }
  }

  const chosenDetails = selection && <dl className="chosen-details">
    <div><dt>Дата аренды</dt><dd>{formatDate(date, { day: "numeric", month: "long", year: "numeric" })}</dd></div>
    <div><dt>Время аренды</dt><dd>{timeLabel(selection.start)}–{timeLabel(selection.end)}</dd></div>
    <div><dt>Продолжительность</dt><dd>{durationLabel(selection.end - selection.start)}</dd></div>
  </dl>;

  if (step === "welcome") return <Welcome onBook={() => goTo("calendar")} />;

  if (step === "confirmation" && confirmation) return <section className="step-screen section-shell" data-screen="confirmation"><Confirmation value={confirmation} onBack={newBooking} /></section>;

  const back = <button className="text-button screen-back" type="button" disabled={busy} onClick={() => { setError(""); goTo(step === "contact" ? "time" : step === "time" ? "calendar" : "welcome"); }}>← Назад</button>;

  if (step === "calendar") return <section className="step-screen calendar-screen section-shell" data-screen="calendar" aria-labelledby="calendar-title">
    {back}<div className="section-heading booking-intro"><div><p className="eyebrow">Ваше время, ваше пространство</p><h2 id="calendar-title" tabIndex={-1} data-step-heading>Давайте запланируем<br /><em>что-то хорошее.</em></h2></div><p>Выберите день и отметьте время в сетке.<br />Всё остальное начинается с вашей идеи.</p></div>
    <div className="booking-card booking-picker"><div className="date-time-panel">
      <div className="step-heading"><span className="step-number">01</span><h3>Когда встретимся?</h3></div>
      <Calendar month={month} selected={date} now={now} bookings={bookings} onMonth={setMonth} onSelect={selectDate} />
      {error && <div className="form-error" role="alert">{error}</div>}<AdminContact />
    </div></div>
  </section>;

  if (step === "time") return <section className="step-screen time-screen section-shell" data-screen="time" aria-labelledby="time-title">
    {back}<div className="step-heading screen-title"><span className="step-number">02</span><h2 id="time-title" tabIndex={-1} data-step-heading>Выберите время</h2></div>
    <div className="booking-card booking-picker"><div className="date-time-panel">
      <TimeGrid date={date} now={now} bookings={bookings} selection={validSelection} onSlot={chooseSlot} onReset={() => { setSelection(null); setError(""); }} />
      {error && <div className="form-error" role="alert">{error}</div>}
      <div className="picker-footer"><p>От 1 часа · шаг 30 минут</p><button className="button button-dark" type="button" disabled={!validSelection} onClick={continueToContact}>Продолжить <span aria-hidden="true"><ArrowIcon /></span></button></div>
      <AdminContact />
    </div></div>
  </section>;

  return <section className="step-screen contacts-screen section-shell" data-screen="contacts" aria-labelledby="contact-title">
    {back}<form className="booking-card contact-step" onSubmit={submit} noValidate ref={formRef}>
      <div className="booking-side-summary"><p className="eyebrow">Ваш выбор</p>{chosenDetails}<button type="button" className="text-button" disabled={busy} onClick={() => { setError(""); goTo("time"); }}>← Изменить дату или время</button><AdminContact /></div>
      <div className="contact-panel"><div className="step-heading"><span className="step-number">03</span><h3 id="contact-title" tabIndex={-1} data-step-heading>Контактные данные</h3></div>
        <p className="contact-caption">Это демонстрационная форма. Используйте только вымышленные данные. Не вводите реальные контакты.</p>
        <ContactForm value={contact} errors={errors} onChange={setContact} />
        <p className="demo-warning" role="note">{DEMO_WARNING}</p>
        {error && <div className="form-error" role="alert" ref={errorRef} tabIndex={-1}>{error}</div>}
        <button className="button button-dark submit-button" type="submit" disabled={busy}>{busy ? "Проверяем доступность…" : "Подтвердить выбор"}<span aria-hidden="true"><ArrowIcon /></span></button>
        <p className="demo-caption">Демонстрационный режим · без сохранения и уведомлений</p>
      </div>
    </form>
  </section>;
}
