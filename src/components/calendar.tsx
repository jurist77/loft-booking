"use client";

import { addDays, addMonths, dateRange, formatDate, isBookableDate, type Booking } from "@/lib/availability";
import { STUDIO } from "@/lib/studio";

type Props = {
  month: string; selected: string; now: Date; bookings: readonly Booking[];
  onMonth: (month: string) => void; onSelect: (date: string) => void;
};

export function Calendar({ month, selected, now, bookings, onMonth, onSelect }: Props) {
  const { first, last } = dateRange(now);
  const beginning = `${month}-01`;
  const offset = (new Date(`${beginning}T12:00:00Z`).getUTCDay() + 6) % 7;
  const nextMonth = addMonths(beginning, 1);
  const days = Math.round((Date.parse(nextMonth) - Date.parse(beginning)) / 86400000);
  const count = Math.ceil((offset + days) / 7) * 7;
  return (
    <div className="calendar">
      <div className="calendar-heading">
        <h4 aria-live="polite">{formatDate(beginning, { month: "long", year: "numeric" }).replace(" г.", "")}</h4>
        <div className="month-arrows">
          <button type="button" className="icon-button" aria-label="Предыдущий месяц" disabled={month <= first.slice(0, 7)} onClick={() => onMonth(addMonths(beginning, -1).slice(0, 7))}>←</button>
          <button type="button" className="icon-button" aria-label="Следующий месяц" disabled={month >= last.slice(0, 7)} onClick={() => onMonth(nextMonth.slice(0, 7))}>→</button>
        </div>
      </div>
      <div className="calendar-grid" role="group" aria-label="Выберите дату">
        {["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Вс"].map((day) => <span className="weekday" key={day}>{day}</span>)}
        {Array.from({ length: count }, (_, i) => {
          const date = addDays(beginning, i - offset);
          if (date.slice(0, 7) !== month) return <span key={date} />;
          const fullyBooked = bookings.filter((b) => b.date === date).reduce((sum, b) => sum + b.end - b.start, 0) >= STUDIO.close - STUDIO.open;
          return <button type="button" key={date} className={`calendar-day ${date === first ? "today" : ""} ${date === selected ? "selected" : ""}`} aria-label={formatDate(date, { day: "numeric", month: "long", year: "numeric" })} aria-pressed={date === selected} aria-current={date === first ? "date" : undefined} disabled={!isBookableDate(date, now)} onClick={() => onSelect(date)}>
            {Number(date.slice(8))}
            {fullyBooked && <span className="day-dot" aria-label="День полностью занят" />}
          </button>;
        })}
      </div>
      <p className="calendar-footnote"><span className="tiny-dot" /> Сегодня · запись до {formatDate(last)}</p>
    </div>
  );
}
