import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Loft Studio — пространство для ваших встреч",
  description: "Тёплое пространство для особенных моментов. Выберите дату и пройдите демонстрационный сценарий бронирования Loft Studio.",
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="ru"><body>{children}</body></html>;
}
