"use client";

import { getSlots, timeLabel, durationLabel, formatDate, type Booking } from "@/lib/availability";
import { selectSlot, type RentalSelection } from "@/lib/selection";

type Props = {
  date: string; bookings: readonly Booking[]; now: Date; selection: RentalSelection | null;
  onSlot: (slot: number) => void; onReset: () => void;
};

export function TimeGrid({ date, bookings, now, selection, onSlot, onReset }: Props) {
  const slots = getSlots(date, bookings, now);
  const noFreeHour = slots.every((slot) => selectSlot(date, slot.start, null, bookings, now).error);
  return <div className="time-grid-panel">
    <div className="time-heading"><h4>{formatDate(date)}</h4><span>07:00–23:00</span></div>
    <div className="slots" role="group" aria-label="Все получасовые слоты" aria-describedby="grid-instructions">
      {slots.map((slot) => {
        const selected = !!selection && slot.start >= selection.start && slot.start < selection.end;
        const allowed = !slot.busy && !slot.past && !selectSlot(date, slot.start, selection, bookings, now).error;
        const state = slot.busy ? "занято" : selected ? "выбрано" : slot.past ? "время прошло" : allowed ? "свободно" : "недоступно для непрерывного интервала";
        return <button type="button" key={slot.start}
          className={`slot ${slot.busy ? "busy-slot" : ""} ${selected ? "selected-slot" : ""}`}
          disabled={!allowed} aria-pressed={selected} aria-label={`${timeLabel(slot.start)} — ${state}`}
          title={`${timeLabel(slot.start)}–${timeLabel(slot.start + 30)}: ${state}`} onClick={() => onSlot(slot.start)}
        >{timeLabel(slot.start)}</button>;
      })}
    </div>
    <div className="slot-legend" role="group" aria-label="Состояния времени">
      <span><i className="legend-free" aria-hidden="true" />Свободно</span>
      <span><i className="legend-busy" aria-hidden="true" /><s>Занято</s></span>
      <span><i className="legend-selected" aria-hidden="true" />Выбрано</span>
    </div>
    <p id="grid-instructions" className="grid-instructions">Первое нажатие — 1 час. Нажмите дальше справа или слева, чтобы продлить. Выбранный слот станет последним в интервале; первый — сбросит выбор. Для другого участка сбросьте выбор.</p>
    <div className="selection-result">
      <output className="selection-summary" aria-live="polite" aria-atomic="true">{selection
        ? `${timeLabel(selection.start)}–${timeLabel(selection.end)} · ${durationLabel(selection.end - selection.start)}`
        : "Время пока не выбрано"}</output>
      <button type="button" className="text-button reset-selection" disabled={!selection} onClick={onReset}>Сбросить выбор</button>
    </div>
    {noFreeHour && <p className="empty-state" role="status">{slots.every((slot) => slot.busy) ? "Этот день полностью занят." : "На этот день не осталось свободного часа."} Выберите другую дату.</p>}
  </div>;
}
