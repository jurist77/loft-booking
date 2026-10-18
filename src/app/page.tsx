import { BookingClient } from "@/components/booking-client";

export default function Home() {
  return <div className="stepper-app">
    <a href="#main" className="skip-link">Перейти к содержимому</a>
    <div className="demo-banner" role="note"><strong>Демонстрационная версия</strong><span>Используйте только вымышленные данные</span></div>
    <header className="site-header section-shell"><span className="wordmark" aria-label="Loft Studio — главная"><span className="brand-symbol" aria-hidden="true">l<span>s</span></span><span>loft<span className="wordmark-light">studio</span><small>ПРОСТРАНСТВО ДЛЯ ВСТРЕЧ</small></span></span><p>Место для ваших встреч.</p></header>
    <main id="main" className="stepper-main" tabIndex={-1}><BookingClient /></main>
  </div>;
}
