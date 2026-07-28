"use client";

import { FormEvent, useMemo, useState } from "react";
import type { ActiveAuditReport, ActiveFinding } from "../../worker/active-audit";

function createToken() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `siteguard-verify-${[...bytes].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function normalizedOrigin(value: string) {
  try {
    const parsed = new URL(/^[a-z][a-z\d+.-]*:\/\//iu.test(value.trim()) ? value.trim() : `https://${value.trim()}`);
    return parsed.origin;
  } catch {
    return "";
  }
}

function FindingCard({ finding }: { finding: ActiveFinding }) {
  const label = finding.status === "pass"
    ? "Пройдено"
    : finding.status === "fail"
      ? "Проблема"
      : finding.status === "warning"
        ? "Внимание"
        : "Информация";
  return (
    <article className={`active-finding finding-${finding.status}`}>
      <div className="active-finding-head">
        <span className={`active-status ${finding.status}`}>{label}</span>
        <small>{finding.severity}</small>
      </div>
      <h3>{finding.title}</h3>
      <p>{finding.evidence}</p>
      {finding.recommendation && <div><strong>Что исправить</strong>{finding.recommendation}</div>}
    </article>
  );
}

function ActiveReport({ report, onReset }: { report: ActiveAuditReport; onReset: () => void }) {
  function download() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `siteguard-active-${new URL(report.target).hostname}-${report.scannedAt.slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return (
    <main className="active-report">
      <section className="active-report-hero">
        <div>
          <span className="active-kicker">Активный отчёт готов</span>
          <h1>{new URL(report.target).hostname}</h1>
          <p>Выполнено {report.metrics.requests} безопасных запросов за {report.metrics.durationMs} мс.</p>
        </div>
        <div className="active-score"><strong>{report.summary.score}</strong><span>из 100</span></div>
        <div className="active-actions">
          <button className="button secondary" type="button" onClick={download}>Скачать JSON</button>
          <button className="button ghost" type="button" onClick={onReset}>Новая проверка</button>
        </div>
      </section>

      <section className="active-summary" aria-label="Сводка">
        <article><strong>{report.summary.passed}</strong><span>пройдено</span></article>
        <article><strong>{report.summary.warnings}</strong><span>замечаний</span></article>
        <article><strong>{report.summary.failed}</strong><span>проблем</span></article>
        <article><strong>{report.summary.informational}</strong><span>справочно</span></article>
      </section>

      <section className="active-findings">
        <div className="active-section-title">
          <span className="active-kicker">Безопасная диагностика</span>
          <h2>Результаты активных проверок</h2>
        </div>
        <div className="active-findings-grid">
          {report.findings.map((finding) => <FindingCard key={finding.id} finding={finding} />)}
        </div>
      </section>

      <section className="active-limitations">
        <strong>Границы режима</strong>
        {report.limitations.map((item) => <p key={item}>{item}</p>)}
      </section>
    </main>
  );
}

export function ActiveAuditApp() {
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<ActiveAuditReport | null>(null);
  const origin = useMemo(() => normalizedOrigin(url), [url]);
  const verificationUrl = origin ? `${origin}/.well-known/siteguard-verification.txt` : "";

  function prepareToken() {
    setToken(createToken());
    setCopied(false);
    setError("");
  }

  async function copyToken() {
    if (!token) return;
    await navigator.clipboard.writeText(token);
    setCopied(true);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const response = await fetch("/api/active-scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ url, verificationToken: token, confirmed }),
      });
      const data = await response.json() as ActiveAuditReport & { message?: string };
      if (!response.ok) throw new Error(data.message || "Не удалось выполнить активную проверку.");
      setReport(data);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Не удалось выполнить активную проверку.");
    } finally {
      setLoading(false);
    }
  }

  if (report) {
    return (
      <>
        <header className="site-header compact">
          <a className="brand" href="/"><span>SG</span><strong>SiteGuard</strong></a>
          <nav><a className="active-nav-return" href="/active/api">API и права</a><a className="active-nav-return" href="/">Пассивная проверка</a><span className="header-status"><i /> Active</span></nav>
        </header>
        <ActiveReport report={report} onReset={() => { setReport(null); setError(""); }} />
      </>
    );
  }

  return (
    <>
      <header className="site-header compact">
        <a className="brand" href="/"><span>SG</span><strong>SiteGuard</strong></a>
        <nav><a className="active-nav-return" href="/active/api">API и права</a><a className="active-nav-return" href="/">Пассивная проверка</a><span className="header-status"><i /> Active</span></nav>
      </header>
      <main className="active-shell">
        <section className="active-intro">
          <div>
            <span className="active-kicker">Отдельный режим · только для владельца</span>
            <h1>Активная проверка без атаки на сайт.</h1>
            <p>
              SiteGuard отправляет ограниченный набор безопасных диагностических запросов и ищет признаки
              SQL-инъекций, HTML/XSS-отражения, ошибок CORS, CSRF и слабой защиты входа.
            </p>
          </div>
          <aside>
            <strong>Что не выполняется</strong>
            <span>Подбор настоящих паролей</span>
            <span>POST, DELETE и загрузка файлов</span>
            <span>Обход авторизации</span>
            <span>Эксплуатация уязвимостей</span>
          </aside>
        </section>

        <form className="active-wizard" onSubmit={submit}>
          <section className="active-step">
            <span className="active-step-number">01</span>
            <div>
              <h2>Укажите сайт</h2>
              <p>Введите публичный адрес страницы, которую вы имеете право проверять.</p>
              <label>
                <span>URL сайта</span>
                <input
                  type="text"
                  inputMode="url"
                  value={url}
                  onChange={(event) => { setUrl(event.target.value); setToken(""); setConfirmed(false); }}
                  placeholder="https://example.com"
                  required
                  disabled={loading}
                />
              </label>
              <button className="button secondary active-prepare" type="button" onClick={prepareToken} disabled={!origin || loading}>
                Создать токен подтверждения
              </button>
            </div>
          </section>

          <section className={`active-step ${token ? "" : "inactive"}`}>
            <span className="active-step-number">02</span>
            <div>
              <h2>Подтвердите владение</h2>
              <p>Создайте текстовый файл по адресу ниже. Внутри должна быть только строка токена.</p>
              <div className="verification-block">
                <span>Адрес файла</span>
                <code>{verificationUrl || "Сначала укажите сайт"}</code>
                <span>Содержимое файла</span>
                <code>{token || "Сначала создайте токен"}</code>
                <button type="button" onClick={copyToken} disabled={!token}>{copied ? "Скопировано" : "Скопировать токен"}</button>
              </div>
            </div>
          </section>

          <section className={`active-step ${token ? "" : "inactive"}`}>
            <span className="active-step-number">03</span>
            <div>
              <h2>Запустите отдельную проверку</h2>
              <p>Файл подтверждения проверяется заново перед каждым запуском.</p>
              <label className="ownership-check">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                  disabled={!token || loading}
                />
                <span>Я владею этим сайтом или имею письменное разрешение на активную проверку.</span>
              </label>
              <button className="button primary active-launch" type="submit" disabled={!token || !confirmed || loading}>
                {loading ? "Выполняется безопасная проверка…" : "Проверить владение и запустить"}
              </button>
              {error && <div className="active-error" role="alert">{error}</div>}
            </div>
          </section>
        </form>

        <section className="active-scope">
          <article><span>01</span><strong>SQL-сигналы</strong><p>Одна безопасная кавычка и сравнение ответа без выполнения SQL-команд.</p></article>
          <article><span>02</span><strong>XSS-отражение</strong><p>Инертный HTML-маркер без JavaScript, обработчиков событий и эксплуатации.</p></article>
          <article><span>03</span><strong>CORS и методы</strong><p>OPTIONS с посторонним Origin и анализ разрешённых методов.</p></article>
          <article><span>04</span><strong>CSRF и вход</strong><p>Анализ публичных форм и признаков rate limiting без попыток авторизации.</p></article>
        </section>
        <section className="api-access-promo">
          <div>
            <span className="active-kicker">Новый отдельный модуль</span>
            <h2>OpenAPI и права двух тестовых аккаунтов</h2>
            <p>Импортируйте Swagger/OpenAPI и безопасно проверьте изоляцию объектов BOLA/IDOR только GET-запросами.</p>
          </div>
          <a className="button secondary" href="/active/api">Открыть API Access</a>
        </section>
      </main>
    </>
  );
}
