"use client";

import { EVENT_TYPES, type ContactErrors, type ContactInput } from "@/lib/validation";

type Props = { value: ContactInput; errors: ContactErrors; onChange: (value: ContactInput) => void };

export function ContactForm({ value, errors, onChange }: Props) {
  function set<K extends keyof ContactInput>(field: K, next: ContactInput[K]) { onChange({ ...value, [field]: next }); }
  const attributes = (field: keyof ContactInput) => ({ "aria-invalid": !!errors[field], "aria-describedby": errors[field] ? `${field}-error` : undefined });
  const error = (field: keyof ContactInput) => errors[field] && <span className="field-error" id={`${field}-error`}>{errors[field]}</span>;
  return (
    <div className="contact-fields">
      <div className="field-pair">
        <label className="field" htmlFor="firstName">Имя <span aria-hidden="true">*</span>
          <input id="firstName" name="firstName" autoComplete="off" placeholder="Например, Тест" value={value.firstName} onChange={(e) => set("firstName", e.target.value)} required maxLength={80} {...attributes("firstName")} />{error("firstName")}
        </label>
        <label className="field" htmlFor="lastName">Фамилия <span aria-hidden="true">*</span>
          <input id="lastName" name="lastName" autoComplete="off" placeholder="Например, Пример" value={value.lastName} onChange={(e) => set("lastName", e.target.value)} required maxLength={80} {...attributes("lastName")} />{error("lastName")}
        </label>
      </div>
      <label className="field" htmlFor="phone">Мобильный телефон <span aria-hidden="true">*</span>
        <input id="phone" name="phone" type="tel" autoComplete="off" inputMode="tel" placeholder="+7 (___) ___-__-__" value={value.phone} onChange={(e) => set("phone", e.target.value)} required maxLength={30} {...attributes("phone")} />{error("phone")}
      </label>
      <label className="field" htmlFor="eventType">Тип мероприятия <span aria-hidden="true">*</span>
        <select id="eventType" name="eventType" value={value.eventType} onChange={(e) => set("eventType", e.target.value)} required {...attributes("eventType")}>
          <option value="">Выберите вид мероприятия</option>{EVENT_TYPES.map((type) => <option key={type}>{type}</option>)}
        </select>{error("eventType")}
      </label>
    </div>
  );
}
