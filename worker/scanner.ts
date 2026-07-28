import type { AuditCategory, AuditCheck, ScanReport } from "./audit-types.ts";
import { auditRepository } from "./repo-audit.ts";
import { auditSite, fetchPublicSite } from "./site-audit.ts";

const CATEGORY_TITLES: Record<string, string> = {
  transport: "HTTPS и транспорт",
  headers: "HTTP-заголовки",
  application: "Клиентская безопасность",
  "supply-chain": "Цепочка поставки",
  privacy: "Cookies и приватность",
  accessibility: "Доступность",
  quality: "Качество и PWA",
  governance: "Управление безопасностью",
  source: "Исходный код и зависимости",
};

function categoryScore(checks: AuditCheck[]): number {
  const weighted = checks.filter((item) => item.status !== "info" && item.weight > 0);
  const maximum = weighted.reduce((sum, item) => sum + item.weight, 0);
  if (!maximum) return 100;
  const penalty = weighted.reduce((sum, item) => {
    if (item.status === "fail") return sum + item.weight;
    if (item.status === "warning") return sum + item.weight * 0.5;
    return sum;
  }, 0);
  return Math.max(0, Math.round(100 - (penalty / maximum) * 100));
}

function grade(score: number): string {
  if (score >= 95) return "A+";
  if (score >= 88) return "A";
  if (score >= 78) return "B";
  if (score >= 65) return "C";
  if (score >= 50) return "D";
  return "F";
}

export async function scanTarget(input: { url: string; repository?: string }, fetcher: typeof fetch = fetch): Promise<ScanReport> {
  const site = await fetchPublicSite(input.url, fetcher);
  const audited = auditSite(site);
  const repository = input.repository ? await auditRepository(input.repository, fetcher) : undefined;
  const allChecks = [...audited.checks, ...(repository?.checks || [])];
  const grouped = new Map<string, AuditCheck[]>();
  for (const item of allChecks) {
    const list = grouped.get(item.category) || [];
    list.push(item);
    grouped.set(item.category, list);
  }
  const categories: AuditCategory[] = [...grouped.entries()].map(([id, checks]) => ({
    id,
    title: CATEGORY_TITLES[id] || id,
    score: categoryScore(checks),
    checks,
  }));
  const score = categoryScore(allChecks);
  return {
    reportVersion: 1,
    id: crypto.randomUUID(),
    scannedAt: new Date().toISOString(),
    target: {
      requestedUrl: site.requestedUrl.toString(),
      finalUrl: site.finalUrl.toString(),
      statusCode: site.response.status,
      redirects: site.redirects,
    },
    summary: {
      score,
      grade: grade(score),
      passed: allChecks.filter((item) => item.status === "pass").length,
      warnings: allChecks.filter((item) => item.status === "warning").length,
      failed: allChecks.filter((item) => item.status === "fail").length,
      informational: allChecks.filter((item) => item.status === "info").length,
    },
    categories,
    metrics: audited.metrics,
    technologies: audited.technologies,
    repository,
    limitations: [
      "Проверка пассивная: SiteGuard не эксплуатирует уязвимости, не подбирает пароли и не изменяет целевой сайт.",
      "TLS-сертификат, открытые порты, WAF, серверная конфигурация и бизнес-логика требуют отдельного авторизованного тестирования.",
      "Анализ GitHub охватывает ограниченный набор публичных файлов и дополняет, но не заменяет локальные SAST, secret scanning и audit.",
      "Результат отражает состояние публичных ответов в момент проверки и не является гарантией отсутствия уязвимостей.",
    ],
  };
}
