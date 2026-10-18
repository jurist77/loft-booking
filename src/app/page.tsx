import { StudioBrand } from "@/components/studio-brand";
import { STUDIO } from "@/lib/studio";
import { BookingClient } from "@/components/booking-client";

export default function Home() {
  return <div className="stepper-app">
    <a href="#main" className="skip-link">Перейти к содержимому</a>
    <div className="demo-banner" role="note"><strong>Демонстрационная версия</strong><span>Используйте только вымышленные данные</span></div>
    <header className="site-header section-shell"><StudioBrand /><p>{STUDIO.tagline}</p></header>
    <main id="main" className="stepper-main" tabIndex={-1}><BookingClient /></main>
  </div>;
}
