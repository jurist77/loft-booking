import { StudioBrand } from "@/components/studio-brand";
import { STUDIO } from "@/lib/studio";
import { BookingClient } from "@/components/booking-client";
import { appMode } from "@/lib/app-mode";

export default function Home() {
  const server = appMode(process.env.APP_MODE) === "server";
  return <div className="stepper-app">
    <a href="#main" className="skip-link">Перейти к содержимому</a>
    <div className="demo-banner" role="note"><strong>{server ? "Серверный режим" : "Демонстрационная версия"}</strong><span>{server ? "Онлайн-бронирование студии" : "Используйте только вымышленные данные"}</span></div>
    <header className="site-header section-shell"><StudioBrand /><p>{STUDIO.tagline}</p></header>
    <main id="main" className="stepper-main" tabIndex={-1}><BookingClient /></main>
  </div>;
}
