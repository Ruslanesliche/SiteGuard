import type { Metadata } from "next";
import { ActiveAuditApp } from "./active-audit-app";

export const metadata: Metadata = {
  title: "SiteGuard Active — авторизованная активная проверка",
  description: "Отдельный безопасный режим активной проверки сайта после подтверждения владения доменом.",
};

export default function ActivePage() {
  return <ActiveAuditApp />;
}
