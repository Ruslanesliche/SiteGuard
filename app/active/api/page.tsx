import type { Metadata } from "next";
import { ApiAccessApp } from "./api-access-app";

export const metadata: Metadata = {
  title: "SiteGuard API Access — OpenAPI и проверка прав",
  description: "Отдельная авторизованная проверка OpenAPI и изоляции объектов между двумя тестовыми аккаунтами.",
};

export default function ApiAccessPage() {
  return <ApiAccessApp />;
}
