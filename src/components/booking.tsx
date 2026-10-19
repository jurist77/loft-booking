"use client";

import { useEffect, useRef, useState } from "react";
import { durationLabel, formatDate, moscowDate, timeLabel, validateInterval, type Booking as BookingData } from "@/lib/availability";
import { BookingClientError, demoBookingService, type BookingService, type Confirmation as ConfirmationData } from "@/lib/booking-service";
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

const EMPTY_CONTACT: ContactInput = { firstName: "", lastName: "", phone: "" };

export function Booking({ initialNow, initialBookings, service = demoBookingService, server = false }: { initialNow: string; initialBookings: BookingData[]; service?: BookingService; server?: boolean }) {
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
  const sending = useRef(false);
  const [uncertain, setUncertain] = useState(false);
  const [retryAt, setRetryAt] = useState(0);
  const [availability, setAvailability] = useState<"idle" | "loading" | "ready" | "error">(server ? "idle" : "ready");
  const [loadRetryAt, setLoadRetryAt] = useState(0);
  const loading = useRef<{ token: number; controller?: AbortController }>({ token: 0 });
  const [confirmation, setConfirmation] = useState<ConfirmationData | null>(null);
  const formRef = useRef<HTMLFormElement>(null);
  const errorRef = useRef<HTMLDivElement>(null);
  const today = moscowDate(now);
  const validSelection = selection && !validateInterval(date, selection.start, selection.end, bookings, now) ? selection : null;

  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), retryAt || loadRetryAt ? 1000 : 15000);
    return () => clearInterval(timer);
  }, [retryAt, loadRetryAt]);
  useEffect(() => () => loading.current.controller?.abort(), []);
  useEffect(() => {
    if (server) return;
    let active = true;
    service.getBookings(new Date()).then((data) => { if (active) setBookings(data); }).catch(() => { if (active) setError("Не удалось загрузить доступность. Обновите страницу."); });
    return () => { active = false; };
  }, [today, server, service]);

  function cancelLoading() { loading.current.controller?.abort(); loading.current.token++; setAvailability(server ? "idle" : "ready"); }
  async function loadAvailability(target: string, preserved: RentalSelection | null, enterTime = true, note = "") {
    cancelLoading(); const token = loading.current.token;
    const controller = new AbortController(); loading.current.controller = controller;
    setAvailability("loading"); setError(note);
    try {
      const fresh = await service.getBookings(new Date(), target, controller.signal);
      if (controller.signal.aborted || token !== loading.current.token) return;
      const current = new Date();
      setBookings(fresh); setNow(current); setAvailability("ready"); setLoadRetryAt(0);
      if (preserved && validateInterval(target, preserved.start, preserved.end, fresh, current)) {
        setSelection(null); setError("Ранее выбранное время больше недоступно. Выберите другой интервал.");
      } else setError(note);
      if (enterTime) goTo("time");
    } catch (cause) {
      if (controller.signal.aborted || token !== loading.current.token) return;
      setAvailability("error");
      setLoadRetryAt(cause instanceof BookingClientError ? cause.retryAt : 0);
      setError([note, cause instanceof BookingClientError ? cause.message : "Не удалось загрузить доступность. Попробуйте ещё раз."].filter(Boolean).join(" "));
    }
  }

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
    if (server) { setBookings([]); void loadAvailability(next, next === date ? selection : null); }
    else goTo("time");
  }
  function chooseSlot(slot: number) {
    if (server && availability !== "ready") return;
    const current = new Date();
    const previous = selection && !validateInterval(date, selection.start, selection.end, bookings, current) ? selection : null;
    const change = selectSlot(date, slot, previous, bookings, current);
    setNow(current); setSelection(change.selection); setError(change.error || "");
  }
  function continueToContact() {
    if (server && availability !== "ready") return;
    const current = new Date();
    const problem = selection ? validateInterval(date, selection.start, selection.end, bookings, current) : "Выберите время аренды.";
    setNow(current);
    if (problem) { setError(problem); return; }
    setError(""); goTo("contact");
  }
  function newBooking() {
    const current = new Date(); const next = moscowDate(current);
    setConfirmation(null); setContact(EMPTY_CONTACT); setErrors({}); setSelection(null);
    cancelLoading(); service.reset?.(); setUncertain(false); setRetryAt(0); setAvailability(server ? "idle" : "ready");
    setDate(next); setMonth(next.slice(0, 7)); setNow(current); setError(""); goTo("welcome");
  }
  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (sending.current || Date.now() < retryAt) return;
    const current = new Date();
    setNow(current);
    const checked = validateContact(contact);
    setErrors(checked.errors);
    const request = selection ? { date, ...selection, contact: { ...contact, phone: checked.phone ?? contact.phone } } : null;
    const retry = request && !Object.keys(checked.errors).length && service.isRetry?.(request);
    const intervalError = selection ? retry ? null : validateInterval(date, selection.start, selection.end, bookings, current) : "Вернитесь к календарю и выберите время.";
    if (intervalError || Object.keys(checked.errors).length) {
      setError(intervalError || "Проверьте отмеченные поля формы.");
      requestAnimationFrame(() => {
        if (Object.keys(checked.errors).length) formRef.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus();
        else errorRef.current?.focus();
      });
      return;
    }
    sending.current = true; setBusy(true); setError("");
    try {
      const value = await service.confirm(request!, current);
      if (server) service.reset?.();
      setConfirmation(value); setContact(EMPTY_CONTACT); setErrors({}); setUncertain(false); setRetryAt(0); goTo("confirmation");
    } catch (cause) {
      if (server) {
        const failure = cause instanceof BookingClientError ? cause : new BookingClientError("unknown", "Результат бронирования не удалось подтвердить. Повторите отправку той же заявки.", 0, true);
        setError(failure.message + (failure.uncertain && failure.kind !== "unknown" ? " Результат предыдущей отправки по-прежнему не подтверждён." : "")); setUncertain(failure.uncertain); setRetryAt(failure.retryAt);
        if (failure.kind === "overlap") {
          setSelection(null); setAvailability("loading"); goTo("time");
          void loadAvailability(date, null, false, failure.message);
        }
      } else {
        setError(cause instanceof Error ? cause.message : "Не удалось проверить интервал. Попробуйте ещё раз.");
        try { setBookings(await service.getBookings(new Date())); } catch { /* Keep the demo's last snapshot and visible error. */ }
      }
      requestAnimationFrame(() => errorRef.current?.focus());
    } finally { sending.current = false; setBusy(false); }
  }

  function backToTime() {
    setError(""); goTo("time");
    if (server) void loadAvailability(date, selection, false);
  }
  function acknowledgeChange() {
    if (window.confirm("Предыдущая заявка могла сохраниться. Изменение данных может создать отдельное бронирование. Разрешить изменение заявки?")) {
      service.acknowledgeChange?.(); setUncertain(false);
    }
  }
  const waiting = Math.max(0, Math.ceil((retryAt - now.getTime()) / 1000));
  const loadWaiting = Math.max(0, Math.ceil((loadRetryAt - now.getTime()) / 1000));
  const availabilityNotice = <>
    {server && availability === "loading" && <p className="contact-caption" role="status">Загружаем доступность…</p>}
    {error && <div className="form-error" role="alert">{error}</div>}
    {server && availability === "error" && <button className="text-button" type="button" disabled={loadWaiting > 0} onClick={() => void loadAvailability(date, selection)}>Повторить загрузку{loadWaiting > 0 ? ` через ${loadWaiting} с` : ""}</button>}
  </>;

  const chosenDetails = selection && <dl className="chosen-details">
    <div><dt>Дата аренды</dt><dd>{formatDate(date, { day: "numeric", month: "long", year: "numeric" })}</dd></div>
    <div><dt>Время аренды</dt><dd>{timeLabel(selection.start)}–{timeLabel(selection.end)}</dd></div>
    <div><dt>Продолжительность</dt><dd>{durationLabel(selection.end - selection.start)}</dd></div>
  </dl>;

  if (step === "welcome") return <Welcome onBook={() => goTo("calendar")} />;

  if (step === "confirmation" && confirmation) return <section className="step-screen section-shell" data-screen="confirmation"><Confirmation value={confirmation} onBack={newBooking} /></section>;

  const back = <button className="text-button screen-back" type="button" disabled={busy || uncertain} onClick={() => {
    if (step === "contact") backToTime();
    else { cancelLoading(); setError(""); goTo(step === "time" ? "calendar" : "welcome"); }
  }}>← Назад</button>;

  if (step === "calendar") return <section className="step-screen calendar-screen section-shell" data-screen="calendar" aria-labelledby="calendar-title">
    {back}<div className="section-heading booking-intro"><div><p className="eyebrow">Ваше время, ваше пространство</p><h2 id="calendar-title" tabIndex={-1} data-step-heading>Давайте запланируем<br /><em>что-то хорошее.</em></h2></div><p>Выберите день и отметьте время в сетке.<br />Всё остальное начинается с вашей идеи.</p></div>
    <div className="booking-card booking-picker" aria-busy={availability === "loading"}><div className="date-time-panel">
      <div className="step-heading"><span className="step-number">01</span><h3>Когда встретимся?</h3></div>
      <Calendar month={month} selected={date} now={now} bookings={bookings} onMonth={setMonth} onSelect={selectDate} />
      {availabilityNotice}<AdminContact />
    </div></div>
  </section>;

  if (step === "time") return <section className="step-screen time-screen section-shell" data-screen="time" aria-labelledby="time-title">
    {back}<div className="step-heading screen-title"><span className="step-number">02</span><h2 id="time-title" tabIndex={-1} data-step-heading>Выберите время</h2></div>
    <div className="booking-card booking-picker" aria-busy={availability === "loading"}><div className="date-time-panel">
      {(!server || availability === "ready") && <TimeGrid date={date} now={now} bookings={bookings} selection={validSelection} onSlot={chooseSlot} onReset={() => { setSelection(null); setError(""); }} />}
      {availabilityNotice}
      {server && availability === "ready" && <button className="text-button" type="button" onClick={() => void loadAvailability(date, selection, false)}>Обновить доступность</button>}
      <div className="picker-footer"><p>От 1 часа · шаг 30 минут</p><button className="button button-dark" type="button" disabled={!validSelection || (server && availability !== "ready")} onClick={continueToContact}>Продолжить <span aria-hidden="true"><ArrowIcon /></span></button></div>
      <AdminContact />
    </div></div>
  </section>;

  return <section className="step-screen contacts-screen section-shell" data-screen="contacts" aria-labelledby="contact-title">
    {back}<form className="booking-card contact-step" onSubmit={submit} noValidate ref={formRef} aria-busy={busy}>
      <div className="booking-side-summary"><p className="eyebrow">Ваш выбор</p>{chosenDetails}<button type="button" className="text-button" disabled={busy || uncertain} onClick={backToTime}>← Изменить дату или время</button><AdminContact /></div>
      <div className="contact-panel"><div className="step-heading"><span className="step-number">03</span><h3 id="contact-title" tabIndex={-1} data-step-heading>Контактные данные</h3></div>
        <p className="contact-caption">{server ? "Укажите контактные данные. Бронирование будет подтверждено после сохранения на сервере." : "Это демонстрационная форма. Используйте только вымышленные данные. Не вводите реальные контакты."}</p>
        <ContactForm value={contact} errors={errors} onChange={setContact} disabled={busy || uncertain} />
        {!server && <p className="demo-warning" role="note">{DEMO_WARNING}</p>}
        {error && <div className="form-error" role="alert" ref={errorRef} tabIndex={-1}>{error}</div>}
        {server && uncertain && <button type="button" className="text-button" disabled={busy} onClick={acknowledgeChange}>Изменить заявку после предупреждения</button>}
        <button className="button button-dark submit-button" type="submit" disabled={busy || waiting > 0}>{busy ? server ? "Отправляем заявку…" : "Проверяем доступность…" : waiting > 0 ? `Повторить через ${waiting} с` : uncertain ? "Безопасно повторить отправку" : "Подтвердить выбор"}<span aria-hidden="true"><ArrowIcon /></span></button>
        <p className="demo-caption">{server ? "Заявка хранится в памяти вкладки до результата. Уведомления пока не отправляются." : "Демонстрационный режим · без сохранения и уведомлений"}</p>
      </div>
    </form>
  </section>;
}
