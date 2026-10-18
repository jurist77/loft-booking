import type { Metadata } from "next";
import "./globals.css";
import { STUDIO } from "@/lib/studio";
import { assetPath } from "@/lib/deployment";

export const metadata: Metadata = {
  title: `${STUDIO.name} — ${STUDIO.tagline}`,
  applicationName: STUDIO.name,
  icons: { icon: [{ url: assetPath(STUDIO.logo.src), type: "image/jpeg" }] },
  description: `Тёплое пространство для особенных моментов. Выберите дату и пройдите демонстрационный сценарий бронирования ${STUDIO.name}.`,
  robots: { index: false, follow: false },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="ru"><body>{children}</body></html>;
}
