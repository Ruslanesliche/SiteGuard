"use client";

import { FormEvent, useEffect, useMemo, useState } from "react";
import type { AuditCategory, AuditCheck, ScanReport } from "../worker/audit-types";

const PHASES = [
  "Проверяем адрес и DNS",
  "Читаем HTTP-заголовки",
  "Анализируем HTML и cookies",
  "Проверяем исходный код",
  "Формируем рекомендации",
];

const COVERAGE = [
  { code: "01", title: "HTTPS и заголовки", copy: "CSP, HSTS, CORS, anti-framing, MIME, Referrer и Permissions Policy." },
  { code: "02", title: "Cookies и приватность", copy: "Secure, HttpOnly, SameSite, публичный кэш и сторонние трекеры." },
  { code: "03", title: "Клиентская безопасность", copy: "Mixed content, опасные DOM-синки, формы, iframe и внешние скрипты." },
  { code: "04", title: "Исходный код", copy: "Секреты, .env, TLS bypass, CORS, Service Worker и права CI." },
  { code: "05", title: "Зависимости", copy: "Публичные npm-пакеты сверяются с базой OSV; проверяется lock-файл и обновления." },
  { code: "06", title: "Качество", copy: "Доступность, PWA, метаданные, вес страницы и состав ресурсов." },
];

function statusLabel(status: AuditCheck["status"]) {
  return status === "pass" ? "Пройдено" : status === "fail" ? "Проблема" : status === "warning" ? "Внимание" : "Информация";
}

function scoreTone(score: number) {
  if (score >= 88) return "excellent";
  if (score >= 65) return "fair";
  return "poor";
}

function downloadReport(report: ScanReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  const hostname = new URL(report.target.finalUrl).hostname.replace(/[^a-z0-9.-]/giu, "-");
  link.href = URL.createObjectURL(blob);
  link.download = `siteguard-${hostname}-${report.scannedAt.slice(0, 10)}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
}

function CheckRow({ item }: { item: AuditCheck }) {
  return (
    <article className={`check-row status-${item.status}`}>
      <span className="check-symbol" aria-hidden="true">
        {item.status === "pass" ? "✓" : item.status === "fail" ? "×" : item.status === "warning" ? "!" : "i"}
      </span>
      <div className="check-copy">
        <div className="check-heading">
          <h4>{item.title}</h4>
          <span className={`status-badge ${item.status}`}>{statusLabel(item.status)}</span>
          {item.severity !== "info" && <span className={`severity severity-${item.severity}`}>{item.severity}</span>}
        </div>
        <p>{item.evidence}</p>
        {item.recommendation && (
          <div className="recommendation">
            <strong>Что исправить</strong>
            <span>{item.recommendation}</span>
          </div>
        )}
      </div>
    </article>
  );
}

function CategoryCard({ category, defaultOpen }: { category: AuditCategory; defaultOpen: boolean }) {
  const failures = category.checks.filter((item) => item.status === "fail").length;
  const warnings = category.checks.filter((item) => item.status === "warning").length;
  return (
    <details className="category-card" open={defaultOpen}>
      <summary>
        <div>
          <span className="category-kicker">{category.checks.length} проверок</span>
          <h3>{category.title}</h3>
        </div>
        <div className="category-summary">
          {failures > 0 && <span className="mini-count fail">{failures} проблем</span>}
          {warnings > 0 && <span className="mini-count warning">{warnings} замечаний</span>}
          <strong className={scoreTone(category.score)}>{category.score}</strong>
        </div>
      </summary>
      <div className="checks-list">
        {category.checks.map((item) => <CheckRow key={item.id} item={item} />)}
      </div>
    </details>
  );
}

function ResultView({ report, onReset }: { report: ScanReport; onReset: () => void }) {
  const urgent = useMemo(
    () => report.categories
      .flatMap((category) => category.checks)
      .filter((item) => item.status === "fail")
      .sort((a, b) => ["critical", "high", "medium", "low"].indexOf(a.severity) - ["critical", "high", "medium", "low"].indexOf(b.severity))
      .slice(0, 4),
    [report],
  );

  return (
    <main className="results-shell" id="report">
      <section className="report-hero">
        <div className="report-target">
          <span className="eyebrow">Отчёт готов</span>
          <h1>{new URL(report.target.finalUrl).hostname}</h1>
          <a href={report.target.finalUrl} target="_blank" rel="noopener noreferrer">{report.target.finalUrl}</a>
          <p>Проверено {new Intl.DateTimeFormat("ru", { dateStyle: "long", timeStyle: "short" }).format(new Date(report.scannedAt))}</p>
        </div>
        <div className={`score-ring ${scoreTone(report.summary.score)}`} style={{ "--score": `${report.summary.score * 3.6}deg` } as React.CSSProperties}>
          <div>
            <strong>{report.summary.score}</strong>
            <span>{report.summary.grade}</span>
          </div>
        </div>
        <div className="report-actions">
          <button className="button secondary" type="button" onClick={() => downloadReport(report)}>Скачать JSON</button>
          <button className="button ghost" type="button" onClick={onReset}>Новая проверка</button>
        </div>
      </section>

      <section className="summary-grid" aria-label="Сводка отчёта">
        <article><span className="metric-dot pass" /><strong>{report.summary.passed}</strong><small>пройдено</small></article>
        <article><span className="metric-dot warning" /><strong>{report.summary.warnings}</strong><small>замечаний</small></article>
        <article><span className="metric-dot fail" /><strong>{report.summary.failed}</strong><small>проблем</small></article>
        <article><span className="metric-dot info" /><strong>{report.summary.informational}</strong><small>справочно</small></article>
      </section>

      {urgent.length > 0 && (
        <section className="priority-card">
          <div className="section-heading">
            <div>
              <span className="eyebrow danger">Приоритет</span>
              <h2>Исправьте в первую очередь</h2>
            </div>
            <span className="priority-count">{urgent.length}</span>
          </div>
          <div className="priority-list">
            {urgent.map((item, index) => (
              <article key={item.id}>
                <span>0{index + 1}</span>
                <div><strong>{item.title}</strong><p>{item.recommendation || item.evidence}</p></div>
                <small>{item.severity}</small>
              </article>
            ))}
          </div>
        </section>
      )}

      <section className="technical-strip">
        <div><span>HTTP</span><strong>{report.metrics.statusCode}</strong></div>
        <div><span>Ответ</span><strong>{report.metrics.responseTimeMs} мс</strong></div>
        <div><span>HTML</span><strong>{Math.round(report.metrics.htmlBytes / 1024)} КБ</strong></div>
        <div><span>Скрипты</span><strong>{report.metrics.scripts}</strong></div>
        <div><span>Сторонние</span><strong>{report.metrics.thirdPartyScripts}</strong></div>
        <div><span>Origin</span><strong>{report.metrics.externalOrigins}</strong></div>
      </section>

      <section className="report-content">
        <div className="section-heading">
          <div>
            <span className="eyebrow">Полный аудит</span>
            <h2>Результаты по направлениям</h2>
          </div>
          <p>Откройте раздел, чтобы увидеть доказательство и конкретное исправление.</p>
        </div>
        <div className="categories">
          {report.categories.map((category) => (
            <CategoryCard
              key={category.id}
              category={category}
              defaultOpen={category.checks.some((item) => item.status === "fail")}
            />
          ))}
        </div>
      </section>

      {report.repository?.error && (
        <div className="notice warning-notice">
          <strong>GitHub-проверка не завершена</strong>
          <p>{report.repository.error}</p>
        </div>
      )}

      <section className="limitations">
        <span className="eyebrow">Границы проверки</span>
        <h2>Что означает этот отчёт</h2>
        <div>
          {report.limitations.map((item, index) => (
            <p key={item}><span>0{index + 1}</span>{item}</p>
          ))}
        </div>
      </section>
    </main>
  );
}

export function SiteGuardApp() {
  const [url, setUrl] = useState("");
  const [repository, setRepository] = useState("");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [phase, setPhase] = useState(0);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!loading) return;
    const timer = window.setInterval(() => setPhase((value) => Math.min(value + 1, PHASES.length - 1)), 1_700);
    return () => window.clearInterval(timer);
  }, [loading]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setReport(null);
    setPhase(0);
    setLoading(true);
    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url, repository: repository || undefined }),
      });
      const data = await response.json() as ScanReport & { message?: string };
      if (!response.ok) throw new Error(data.message || "Не удалось выполнить проверку.");
      setReport(data);
      window.requestAnimationFrame(() => document.getElementById("report")?.focus());
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Не удалось выполнить проверку.");
    } finally {
      setLoading(false);
    }
  }

  if (report) {
    return (
      <>
        <Header compact />
        <ResultView report={report} onReset={() => { setReport(null); setError(""); window.scrollTo({ top: 0, behavior: "smooth" }); }} />
        <Footer />
      </>
    );
  }

  return (
    <>
      <Header />
      <main>
        <section className="hero">
          <div className="hero-grid" aria-hidden="true" />
          <div className="hero-content">
            <div className="hero-copy">
              <span className="eyebrow"><i /> Пассивный аудит безопасности</span>
              <h1>Найдите слабые места <em>до</em> злоумышленников.</h1>
              <p>SiteGuard проверяет публичный сайт и его исходный код по тем же направлениям, которые используют при профессиональном первичном аудите.</p>
              <div className="trust-row">
                <span>Без эксплуатации</span>
                <span>Данные не сохраняются</span>
                <span>Публичные ресурсы</span>
              </div>
            </div>

            <form className="scan-card" onSubmit={submit}>
              <div className="scan-card-head">
                <div><span className="live-dot" /><strong>Новая проверка</strong></div>
                <span>v1.0</span>
              </div>
              <label>
                <span>URL сайта <b>*</b></span>
                <input
                  type="text"
                  inputMode="url"
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://example.com"
                  autoComplete="url"
                  required
                  disabled={loading}
                />
              </label>
              <label>
                <span>Публичный GitHub <small>необязательно</small></span>
                <input
                  type="text"
                  inputMode="url"
                  value={repository}
                  onChange={(event) => setRepository(event.target.value)}
                  placeholder="github.com/owner/repository"
                  autoComplete="off"
                  disabled={loading}
                />
              </label>
              <button className="button primary" type="submit" disabled={loading}>
                {loading ? "Выполняется проверка…" : "Проверить сайт"}
                <span aria-hidden="true">→</span>
              </button>
              {loading && (
                <div className="scan-progress" aria-live="polite">
                  <div><span style={{ width: `${((phase + 1) / PHASES.length) * 100}%` }} /></div>
                  <p><i /> {PHASES[phase]}</p>
                </div>
              )}
              {error && <div className="form-error" role="alert">{error}</div>}
              <p className="form-note">Отправляя URL, вы подтверждаете право проверять этот публичный ресурс.</p>
            </form>
          </div>
        </section>

        <section className="coverage" id="coverage">
          <div className="section-heading">
            <div>
              <span className="eyebrow">Матрица покрытия</span>
              <h2>Одна проверка. Все основные направления.</h2>
            </div>
            <p>Отчёт разделяет доказательства, риск и конкретное исправление — без расплывчатых рекомендаций.</p>
          </div>
          <div className="coverage-grid">
            {COVERAGE.map((item) => (
              <article key={item.code}>
                <span>{item.code}</span>
                <h3>{item.title}</h3>
                <p>{item.copy}</p>
              </article>
            ))}
          </div>
        </section>

        <section className="method" id="method">
          <div>
            <span className="eyebrow">Безопасная методика</span>
            <h2>Проверяет защиту, а не атакует сайт.</h2>
          </div>
          <div className="method-list">
            <p><span>01</span><strong>Только публичные ответы</strong>SiteGuard выполняет обычные GET-запросы и не обходит авторизацию.</p>
            <p><span>02</span><strong>SSRF-защита</strong>Локальные IP, служебные домены, нестандартные порты и опасные redirect блокируются.</p>
            <p><span>03</span><strong>Без хранения</strong>URL, HTML и исходный код используются только для текущего отчёта.</p>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}

function Header({ compact = false }: { compact?: boolean }) {
  return (
    <header className={`site-header ${compact ? "compact" : ""}`}>
      <a className="brand" href="/" aria-label="SiteGuard — главная"><span>SG</span><strong>SiteGuard</strong></a>
      <nav aria-label="Основная навигация">
        {!compact && <><a href="#coverage">Проверки</a><a href="#method">Методика</a></>}
        <span className="header-status"><i /> Сервис готов</span>
      </nav>
    </header>
  );
}

function Footer() {
  return (
    <footer>
      <a className="brand" href="/"><span>SG</span><strong>SiteGuard</strong></a>
      <p>Пассивный аудит публичных сайтов. Не заменяет авторизованный penetration test.</p>
      <span>© {new Date().getFullYear()}</span>
    </footer>
  );
}
