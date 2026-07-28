import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SiteGuard — аудит безопасности сайтов",
  description: "Пассивная проверка сайта, HTTP-заголовков, cookies, исходного кода GitHub и npm-зависимостей с понятным отчётом.",
  metadataBase: new URL("https://siteguard-ruslan-toxeitov.rus-tokseitov.chatgpt.site"),
  openGraph: {
    title: "SiteGuard — найдите слабые места до злоумышленников",
    description: "Пассивный аудит URL, заголовков, cookies, PWA, исходного кода и зависимостей.",
    type: "website",
    locale: "ru_RU",
    images: [{ url: "/og.png", width: 1731, height: 908, alt: "SiteGuard — аудит безопасности сайтов" }],
  },
  twitter: {
    card: "summary_large_image",
    images: ["/og.png"],
  },
  robots: { index: true, follow: true },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="ru">
      <body>{children}</body>
    </html>
  );
}
