"use client";

import { CHANNELS, EVENT_TYPES, type ContactErrors, type ContactInput } from "@/lib/validation";
import { ArrowIcon, MessageIcon } from "./icons";

type Props = { value: ContactInput; errors: ContactErrors; onChange: (value: ContactInput) => void };

export function ContactForm({ value, errors, onChange }: Props) {
  function set<K extends keyof ContactInput>(field: K, next: ContactInput[K]) { onChange({ ...value, [field]: next }); }
  const attributes = (field: keyof ContactInput) => ({ "aria-invalid": !!errors[field], "aria-describedby": errors[field] ? `${field}-error` : undefined });
  const error = (field: keyof ContactInput) => errors[field] && <span className="field-error" id={`${field}-error`}>{errors[field]}</span>;
  return (
    <div className="contact-fields">
      <div className="field-pair">
        <label className="field" htmlFor="firstName">Имя <span aria-hidden="true">*</span>
          <input id="firstName" name="firstName" autoComplete="given-name" placeholder="Ваше имя" value={value.firstName} onChange={(e) => set("firstName", e.target.value)} required maxLength={80} {...attributes("firstName")} />{error("firstName")}
        </label>
        <label className="field" htmlFor="lastName">Фамилия <span aria-hidden="true">*</span>
          <input id="lastName" name="lastName" autoComplete="family-name" placeholder="Ваша фамилия" value={value.lastName} onChange={(e) => set("lastName", e.target.value)} required maxLength={80} {...attributes("lastName")} />{error("lastName")}
        </label>
      </div>
      <label className="field" htmlFor="phone">Телефон <span aria-hidden="true">*</span>
        <input id="phone" name="phone" type="tel" autoComplete="tel" inputMode="tel" placeholder="+7 (___) ___-__-__" value={value.phone} onChange={(e) => set("phone", e.target.value)} required maxLength={30} {...attributes("phone")} />{error("phone")}
      </label>
      <label className="field" htmlFor="eventType">Что планируете? <span aria-hidden="true">*</span>
        <select id="eventType" name="eventType" value={value.eventType} onChange={(e) => set("eventType", e.target.value)} required {...attributes("eventType")}>
          <option value="">Выберите вид мероприятия</option>{EVENT_TYPES.map((type) => <option key={type}>{type}</option>)}
        </select>{error("eventType")}
      </label>
      <fieldset className="channel-fieldset" tabIndex={-1} aria-describedby={errors.channel ? "channel-error" : "channel-note"} aria-invalid={!!errors.channel}>
        <legend>Канал уведомления <span aria-hidden="true">*</span></legend>
        <div className="channel-options">{CHANNELS.map((channel) => <label className={`channel-option ${value.channel === channel ? "active" : ""}`} key={channel}>
          <input type="radio" name="channel" value={channel} checked={value.channel === channel} onChange={() => set("channel", channel)} required />
          <span aria-hidden="true">{channel === "Telegram" ? <ArrowIcon /> : <MessageIcon />}</span>{channel}
        </label>)}</div>
        <p className="field-hint" id="channel-note">В демоверсии сообщения не отправляются.</p>{error("channel")}
      </fieldset>
      <label className="consent"><input type="checkbox" name="consent" checked={value.consent} onChange={(e) => set("consent", e.target.checked)} required {...attributes("consent")} /><span>Я согласен(на) на обработку персональных данных для оформления бронирования. <span className="muted">В демоверсии данные не сохраняются и не отправляются.</span></span></label>{error("consent")}
    </div>
  );
}
