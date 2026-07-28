"use client";

import { FormEvent, useMemo, useState } from "react";
import type {
  ApiAccessFinding,
  ApiAccessReport,
  ApiEndpoint,
  ApiInventoryReport,
} from "../../../worker/api-access-audit";

function createToken() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return `siteguard-verify-${[...bytes].map((value) => value.toString(16).padStart(2, "0")).join("")}`;
}

function normalizedOrigin(value: string) {
  try {
    return new URL(/^[a-z][a-z\d+.-]*:\/\//iu.test(value.trim()) ? value.trim() : `https://${value.trim()}`).origin;
  } catch {
    return "";
  }
}

function statusLabel(status: ApiAccessFinding["status"]) {
  if (status === "pass") return "Пройдено";
  if (status === "fail") return "Проблема";
  if (status === "warning") return "Внимание";
  return "Информация";
}

function FindingCard({ finding }: { finding: ApiAccessFinding }) {
  return (
    <article className={`active-finding finding-${finding.status}`}>
      <div className="active-finding-head">
        <span className={`active-status ${finding.status}`}>{statusLabel(finding.status)}</span>
        <small>{finding.severity}</small>
      </div>
      <h3>{finding.title}</h3>
      <p>{finding.evidence}</p>
      {finding.recommendation && <div><strong>Что исправить</strong>{finding.recommendation}</div>}
    </article>
  );
}

function ApiReport({ report, onReset }: { report: ApiAccessReport; onReset: () => void }) {
  function download() {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `siteguard-api-access-${new URL(report.target).hostname}-${report.scannedAt.slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return (
    <main className="active-report">
      <section className="active-report-hero">
        <div>
          <span className="active-kicker">Отчёт API Access готов</span>
          <h1>{report.endpointTemplate}</h1>
          <p>{new URL(report.target).hostname} · {report.metrics.requests} GET-запросов · {report.metrics.durationMs} мс</p>
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

      <section className="probe-matrix" aria-label="Матрица запросов">
        <div className="active-section-title">
          <span className="active-kicker">Матрица доступа</span>
          <h2>Что вернул каждый контекст</h2>
        </div>
        <div className="probe-matrix-grid">
          {report.probes.map((probe) => (
            <article key={probe.label}>
              <span>{probe.label.replaceAll("-", " ")}</span>
              <strong>HTTP {probe.status}</strong>
              <small>{probe.bytes} байт · {probe.contentType}</small>
            </article>
          ))}
        </div>
      </section>

      <section className="active-findings">
        <div className="active-section-title">
          <span className="active-kicker">OWASP API Security</span>
          <h2>Результаты проверки прав</h2>
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

export function ApiAccessApp() {
  const [url, setUrl] = useState("");
  const [verificationToken, setVerificationToken] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [specificationLocation, setSpecificationLocation] = useState("/openapi.json");
  const [inventory, setInventory] = useState<ApiInventoryReport | null>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState("");
  const [pathA, setPathA] = useState("");
  const [pathB, setPathB] = useState("");
  const [tokenA, setTokenA] = useState("");
  const [tokenB, setTokenB] = useState("");
  const [showTokens, setShowTokens] = useState(false);
  const [copied, setCopied] = useState(false);
  const [loadingInventory, setLoadingInventory] = useState(false);
  const [loadingAudit, setLoadingAudit] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<ApiAccessReport | null>(null);
  const origin = useMemo(() => normalizedOrigin(url), [url]);
  const verificationUrl = origin ? `${origin}/.well-known/siteguard-verification.txt` : "";
  const getEndpoints = useMemo(
    () => inventory?.endpoints.filter((endpoint: ApiEndpoint) => endpoint.method === "GET") || [],
    [inventory],
  );

  function prepareToken() {
    setVerificationToken(createToken());
    setInventory(null);
    setCopied(false);
    setError("");
  }

  async function copyToken() {
    if (!verificationToken) return;
    await navigator.clipboard.writeText(verificationToken);
    setCopied(true);
  }

  async function loadInventory() {
    setError("");
    setLoadingInventory(true);
    try {
      const response = await fetch("/api/api-inventory", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          url,
          verificationToken,
          specificationLocation,
          confirmed,
        }),
      });
      const data = await response.json() as ApiInventoryReport & { message?: string };
      if (!response.ok) throw new Error(data.message || "Не удалось импортировать OpenAPI.");
      setInventory(data);
      const firstGet = data.endpoints.find((endpoint) => endpoint.method === "GET");
      setSelectedEndpoint(firstGet?.path || "");
    } catch (requestError) {
      setInventory(null);
      setError(requestError instanceof Error ? requestError.message : "Не удалось импортировать OpenAPI.");
    } finally {
      setLoadingInventory(false);
    }
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setLoadingAudit(true);
    try {
      const response = await fetch("/api/api-access-scan", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          url,
          verificationToken,
          specificationLocation,
          endpointTemplate: selectedEndpoint,
          accountAPath: pathA,
          accountBPath: pathB,
          accountAToken: tokenA,
          accountBToken: tokenB,
          confirmed,
        }),
      });
      const data = await response.json() as ApiAccessReport & { message?: string };
      if (!response.ok) throw new Error(data.message || "Не удалось проверить права API.");
      setTokenA("");
      setTokenB("");
      setReport(data);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Не удалось проверить права API.");
    } finally {
      setLoadingAudit(false);
    }
  }

  if (report) {
    return (
      <>
        <header className="site-header compact">
          <a className="brand" href="/"><span>SG</span><strong>SiteGuard</strong></a>
          <nav><a className="active-nav-return" href="/active">Обычный Active</a><span className="header-status"><i /> API Access</span></nav>
        </header>
        <ApiReport report={report} onReset={() => { setReport(null); setError(""); }} />
      </>
    );
  }

  return (
    <>
      <header className="site-header compact">
        <a className="brand" href="/"><span>SG</span><strong>SiteGuard</strong></a>
        <nav><a className="active-nav-return" href="/active">Обычный Active</a><span className="header-status"><i /> API Access</span></nav>
      </header>
      <main className="active-shell api-access-shell">
        <section className="active-intro api-access-intro">
          <div>
            <span className="active-kicker">Отдельный модуль · OpenAPI + два тестовых аккаунта</span>
            <h1>Проверьте, видит ли один пользователь данные другого.</h1>
            <p>
              SiteGuard импортирует GET-маршруты из OpenAPI и сравнивает доступ к двум тестовым объектам
              без изменения данных, перебора паролей и сохранения токенов.
            </p>
          </div>
          <aside>
            <strong>Жёсткие ограничения</strong>
            <span>Только подтверждённый домен</span>
            <span>Только GET из OpenAPI</span>
            <span>Ровно семь запросов</span>
            <span>Только тестовые аккаунты</span>
          </aside>
        </section>

        <form className="active-wizard" onSubmit={submit}>
          <section className="active-step">
            <span className="active-step-number">01</span>
            <div>
              <h2>Сайт и подтверждение</h2>
              <p>Укажите сайт и разместите одноразовый токен в well-known файле.</p>
              <label>
                <span>URL сайта</span>
                <input
                  type="text"
                  inputMode="url"
                  value={url}
                  onChange={(event) => {
                    setUrl(event.target.value);
                    setVerificationToken("");
                    setInventory(null);
                    setConfirmed(false);
                  }}
                  placeholder="https://api.example.com"
                  required
                  disabled={loadingInventory || loadingAudit}
                />
              </label>
              <button className="button secondary active-prepare" type="button" onClick={prepareToken} disabled={!origin}>
                Создать токен подтверждения
              </button>
              {verificationToken && (
                <div className="verification-block api-verification">
                  <span>Адрес файла</span>
                  <code>{verificationUrl}</code>
                  <span>Содержимое</span>
                  <code>{verificationToken}</code>
                  <button type="button" onClick={copyToken}>{copied ? "Скопировано" : "Скопировать"}</button>
                </div>
              )}
              <label className="ownership-check api-confirm">
                <input
                  type="checkbox"
                  checked={confirmed}
                  onChange={(event) => setConfirmed(event.target.checked)}
                  disabled={!verificationToken}
                />
                <span>Я владею сайтом или имею письменное разрешение и использую только тестовые аккаунты.</span>
              </label>
            </div>
          </section>

          <section className={`active-step ${verificationToken && confirmed ? "" : "inactive"}`}>
            <span className="active-step-number">02</span>
            <div>
              <h2>Импорт OpenAPI</h2>
              <p>Поддерживаются OpenAPI 3.x и Swagger 2.0 в JSON. Файл должен находиться на том же домене.</p>
              <label>
                <span>Путь к спецификации</span>
                <input
                  type="text"
                  value={specificationLocation}
                  onChange={(event) => { setSpecificationLocation(event.target.value); setInventory(null); }}
                  placeholder="/openapi.json"
                  required
                  disabled={!verificationToken || !confirmed || loadingInventory || loadingAudit}
                />
              </label>
              <button
                className="button secondary active-prepare"
                type="button"
                onClick={loadInventory}
                disabled={!verificationToken || !confirmed || loadingInventory || loadingAudit}
              >
                {loadingInventory ? "Импортируем…" : "Проверить владение и импортировать"}
              </button>
              {inventory && (
                <div className="inventory-summary">
                  <div>
                    <span>API</span>
                    <strong>{inventory.title}</strong>
                    <small>Версия {inventory.apiVersion} · OpenAPI {inventory.openApiVersion}</small>
                  </div>
                  <div>
                    <span>Маршруты</span>
                    <strong>{inventory.endpoints.length}</strong>
                    <small>GET: {getEndpoints.length}{inventory.truncated ? " · список ограничен" : ""}</small>
                  </div>
                </div>
              )}
            </div>
          </section>

          <section className={`active-step ${inventory && getEndpoints.length ? "" : "inactive"}`}>
            <span className="active-step-number">03</span>
            <div>
              <h2>Два объекта и два аккаунта</h2>
              <p>Выберите GET-шаблон и укажите реальные пути двух объектов, принадлежащих разным тестовым аккаунтам.</p>
              <label>
                <span>GET-маршрут из OpenAPI</span>
                <select
                  value={selectedEndpoint}
                  onChange={(event) => setSelectedEndpoint(event.target.value)}
                  disabled={!inventory || loadingAudit}
                  required
                >
                  {getEndpoints.map((endpoint) => (
                    <option key={endpoint.path} value={endpoint.path}>
                      {endpoint.path} — {endpoint.summary}{endpoint.protected ? " · auth" : ""}
                    </option>
                  ))}
                </select>
              </label>
              <div className="api-two-columns">
                <label>
                  <span>Путь объекта аккаунта A</span>
                  <input
                    type="text"
                    value={pathA}
                    onChange={(event) => setPathA(event.target.value)}
                    placeholder="/api/users/101"
                    required
                    disabled={!inventory || loadingAudit}
                  />
                </label>
                <label>
                  <span>Путь объекта аккаунта B</span>
                  <input
                    type="text"
                    value={pathB}
                    onChange={(event) => setPathB(event.target.value)}
                    placeholder="/api/users/202"
                    required
                    disabled={!inventory || loadingAudit}
                  />
                </label>
                <label>
                  <span>Bearer-токен тестового аккаунта A</span>
                  <input
                    type={showTokens ? "text" : "password"}
                    value={tokenA}
                    onChange={(event) => setTokenA(event.target.value)}
                    autoComplete="off"
                    required
                    minLength={12}
                    disabled={!inventory || loadingAudit}
                  />
                </label>
                <label>
                  <span>Bearer-токен тестового аккаунта B</span>
                  <input
                    type={showTokens ? "text" : "password"}
                    value={tokenB}
                    onChange={(event) => setTokenB(event.target.value)}
                    autoComplete="off"
                    required
                    minLength={12}
                    disabled={!inventory || loadingAudit}
                  />
                </label>
              </div>
              <label className="ownership-check api-token-visibility">
                <input type="checkbox" checked={showTokens} onChange={(event) => setShowTokens(event.target.checked)} />
                <span>Показывать тестовые токены на этом устройстве</span>
              </label>
              <div className="credential-note">
                Токены используются только для пяти GET-запросов, не сохраняются и не включаются в отчёт.
              </div>
              <button className="button primary active-launch" type="submit" disabled={!inventory || loadingAudit}>
                {loadingAudit ? "Сравниваем права…" : "Запустить отдельную проверку API"}
              </button>
              {error && <div className="active-error" role="alert">{error}</div>}
            </div>
          </section>
        </form>
        {error && !inventory && <div className="active-error api-page-error" role="alert">{error}</div>}
      </main>
    </>
  );
}
