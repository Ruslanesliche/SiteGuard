import { assertPublicDns, normalizePublicUrl } from "./url-safety.ts";

const ACTIVE_TIMEOUT_MS = 15_000;
const MAX_RESPONSE_BYTES = 350_000;
const MAX_REDIRECTS = 3;

export type ActiveFindingStatus = "pass" | "warning" | "fail" | "info";
export type ActiveSeverity = "high" | "medium" | "low" | "info";

export interface ActiveFinding {
  id: string;
  title: string;
  status: ActiveFindingStatus;
  severity: ActiveSeverity;
  evidence: string;
  recommendation?: string;
}

export interface ActiveAuditReport {
  reportVersion: 1;
  mode: "authorized-safe-active";
  id: string;
  scannedAt: string;
  target: string;
  verificationUrl: string;
  summary: {
    score: number;
    passed: number;
    warnings: number;
    failed: number;
    informational: number;
  };
  metrics: {
    requests: number;
    durationMs: number;
    baselineStatus: number;
    reflectedStatus: number;
    inputProbeStatus: number;
    optionsStatus: number;
  };
  findings: ActiveFinding[];
  limitations: string[];
}

interface ProbeResponse {
  status: number;
  headers: Headers;
  body: string;
}

interface SafeRequestOptions {
  method?: "GET" | "OPTIONS";
  headers?: Record<string, string>;
}

export function isValidVerificationToken(value: unknown): value is string {
  return typeof value === "string" && /^siteguard-verify-[a-f0-9]{32}$/u.test(value);
}

function finding(
  id: string,
  title: string,
  status: ActiveFindingStatus,
  severity: ActiveSeverity,
  evidence: string,
  recommendation?: string,
): ActiveFinding {
  return { id, title, status, severity, evidence, recommendation };
}

async function readLimited(response: Response): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > MAX_RESPONSE_BYTES) {
      await reader.cancel();
      throw new Error("Ответ сайта превышает безопасный лимит активной проверки.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

async function safeRequest(
  input: URL,
  allowedOrigin: string,
  options: SafeRequestOptions,
  fetcher: typeof fetch,
): Promise<ProbeResponse> {
  let current = new URL(input);
  for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
    if (current.origin !== allowedOrigin) {
      throw new Error("Редирект активной проверки вышел за пределы подтверждённого домена.");
    }
    await assertPublicDns(current, fetcher);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), ACTIVE_TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetcher(current, {
        method: options.method || "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          accept: "text/html,text/plain;q=0.9,*/*;q=0.2",
          "cache-control": "no-cache",
          "user-agent": "SiteGuard-Active/1.0 (+authorized-safe-audit)",
          ...options.headers,
        },
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error("Сайт не ответил за 15 секунд во время активной проверки.");
      }
      throw new Error("Не удалось выполнить безопасный диагностический запрос.");
    } finally {
      clearTimeout(timeout);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error("Сайт вернул редирект без адреса назначения.");
      current = normalizePublicUrl(new URL(location, current).toString());
      continue;
    }

    return {
      status: response.status,
      headers: new Headers(response.headers),
      body: await readLimited(response),
    };
  }
  throw new Error("Слишком много редиректов во время активной проверки.");
}

function sqlErrorEvidence(body: string): string | null {
  const signatures = [
    /SQL syntax.*MySQL/iu,
    /Warning.*mysql_/iu,
    /PostgreSQL.*ERROR/iu,
    /unterminated quoted string/iu,
    /SQLite(?:3)?::(?:Exception|SQLException)/iu,
    /Microsoft OLE DB Provider for SQL Server/iu,
    /ORA-\d{4,5}/iu,
    /SQLSTATE\[[A-Z0-9]+\]/iu,
  ];
  return signatures.find((pattern) => pattern.test(body))?.source || null;
}

function stateChangingForms(html: string): { total: number; withoutToken: number; passwordForms: number } {
  const forms = [...html.matchAll(/<form\b[\s\S]*?<\/form>/giu)].map((match) => match[0]);
  let total = 0;
  let withoutToken = 0;
  let passwordForms = 0;
  for (const form of forms) {
    if (/type\s*=\s*["']?password/iu.test(form)) passwordForms += 1;
    const method = form.match(/\bmethod\s*=\s*["']?([a-z]+)/iu)?.[1]?.toLowerCase() || "get";
    if (!["post", "put", "patch", "delete"].includes(method)) continue;
    total += 1;
    const hasToken = /name\s*=\s*["'][^"']*(?:csrf|xsrf|authenticity|nonce|token)[^"']*["']/iu.test(form);
    if (!hasToken) withoutToken += 1;
  }
  return { total, withoutToken, passwordForms };
}

function summarize(findings: ActiveFinding[]) {
  const passed = findings.filter((item) => item.status === "pass").length;
  const warnings = findings.filter((item) => item.status === "warning").length;
  const failed = findings.filter((item) => item.status === "fail").length;
  const informational = findings.filter((item) => item.status === "info").length;
  const penalty = findings.reduce((sum, item) => {
    if (item.status === "pass" || item.status === "info") return sum;
    const severity = item.severity === "high" ? 18 : item.severity === "medium" ? 11 : 6;
    return sum + (item.status === "fail" ? severity : Math.ceil(severity / 2));
  }, 0);
  return { score: Math.max(0, 100 - penalty), passed, warnings, failed, informational };
}

export async function runActiveAudit(
  input: string,
  verificationToken: string,
  fetcher: typeof fetch = fetch,
): Promise<ActiveAuditReport> {
  if (!isValidVerificationToken(verificationToken)) {
    throw new Error("Токен подтверждения имеет неверный формат.");
  }

  const target = normalizePublicUrl(input);
  const allowedOrigin = target.origin;
  const verificationUrl = new URL("/.well-known/siteguard-verification.txt", allowedOrigin);
  verificationUrl.searchParams.set("check", verificationToken.slice(-12));
  const started = Date.now();

  const verification = await safeRequest(verificationUrl, allowedOrigin, { method: "GET" }, fetcher);
  if (verification.status !== 200 || verification.body.trim() !== verificationToken) {
    throw new Error(
      "Подтверждение владения не найдено. Опубликуйте токен без лишнего текста в /.well-known/siteguard-verification.txt.",
    );
  }

  const probeId = crypto.randomUUID().replace(/-/gu, "").slice(0, 16);
  const reflectionPayload = `<siteguard-probe data-id="${probeId}">`;
  const reflectionUrl = new URL(target);
  reflectionUrl.searchParams.set("siteguard_reflection", reflectionPayload);
  const inputPayload = `SG_${probeId}'"`;
  const inputUrl = new URL(target);
  inputUrl.searchParams.set("siteguard_input", inputPayload);

  const baseline = await safeRequest(target, allowedOrigin, { method: "GET" }, fetcher);
  const reflected = await safeRequest(reflectionUrl, allowedOrigin, { method: "GET" }, fetcher);
  const inputProbe = await safeRequest(inputUrl, allowedOrigin, { method: "GET" }, fetcher);
  const optionsProbe = await safeRequest(target, allowedOrigin, {
    method: "OPTIONS",
    headers: {
      origin: "https://siteguard-audit.invalid",
      "access-control-request-method": "POST",
      "access-control-request-headers": "content-type",
    },
  }, fetcher);

  const findings: ActiveFinding[] = [
    finding(
      "ownership",
      "Подтверждение владения",
      "pass",
      "info",
      `Файл подтверждения получен с ${new URL(verificationUrl).pathname}.`,
    ),
  ];

  const rawReflection = reflected.body.includes(reflectionPayload);
  findings.push(finding(
    "html-reflection",
    "Безопасное отражение пользовательского ввода",
    rawReflection ? "fail" : "pass",
    rawReflection ? "high" : "info",
    rawReflection
      ? "Инертный HTML-маркер вернулся в ответе без кодирования. Это признак возможной HTML/XSS-инъекции."
      : "Инертный HTML-маркер не отразился в ответе без кодирования.",
    rawReflection ? "Кодируйте пользовательские данные по контексту вывода и включите строгую CSP." : undefined,
  ));

  const baselineSql = sqlErrorEvidence(baseline.body);
  const probeSql = sqlErrorEvidence(inputProbe.body);
  const serverErrorDelta = baseline.status < 500 && inputProbe.status >= 500;
  const sqlSignal = Boolean((probeSql && probeSql !== baselineSql) || serverErrorDelta);
  findings.push(finding(
    "sql-error-signal",
    "Признаки SQL-инъекции и раскрытия ошибок",
    sqlSignal ? "fail" : "pass",
    sqlSignal ? "high" : "info",
    sqlSignal
      ? "После безопасной кавычки изменился статус ответа или появилась сигнатура ошибки базы данных."
      : "Безопасная кавычка не вызвала новых ошибок базы данных или серверного сбоя.",
    sqlSignal
      ? "Используйте параметризованные запросы, не показывайте ошибки БД пользователю и проверьте точку вручную в тестовой среде."
      : undefined,
  ));

  const responseDelta = Math.abs(inputProbe.body.length - baseline.body.length);
  findings.push(finding(
    "input-differential",
    "Стабильность обработки необычного ввода",
    serverErrorDelta || responseDelta > Math.max(4_000, baseline.body.length * 0.35) ? "warning" : "pass",
    "medium",
    `Статусы: обычный ${baseline.status}, проверочный ${inputProbe.status}; разница ответа ${responseDelta} байт.`,
    serverErrorDelta || responseDelta > Math.max(4_000, baseline.body.length * 0.35)
      ? "Проверьте обработчик параметра: валидируйте тип, длину и допустимые символы до обращения к данным."
      : undefined,
  ));

  const allowOrigin = optionsProbe.headers.get("access-control-allow-origin") || "";
  const allowCredentials = optionsProbe.headers.get("access-control-allow-credentials") === "true";
  const reflectedForeignOrigin = allowOrigin === "https://siteguard-audit.invalid";
  const permissiveCors = allowOrigin === "*";
  const unsafeCors = reflectedForeignOrigin && allowCredentials;
  const corsStatus: ActiveFindingStatus = unsafeCors
    ? "fail"
    : reflectedForeignOrigin || permissiveCors
      ? "warning"
      : "pass";
  findings.push(finding(
    "cors-probe",
    "CORS для постороннего Origin",
    corsStatus,
    unsafeCors ? "high" : reflectedForeignOrigin || permissiveCors ? "medium" : "info",
    reflectedForeignOrigin || permissiveCors
      ? `Сервер разрешил посторонний Origin: ${allowOrigin}${allowCredentials ? " вместе с credentials" : ""}.`
      : "Посторонний Origin не получил разрешение CORS.",
    reflectedForeignOrigin || permissiveCors
      ? "Разрешайте только точный список доверенных Origin и не сочетайте широкое правило с credentials."
      : undefined,
  ));

  const allowedMethods = (optionsProbe.headers.get("allow") || optionsProbe.headers.get("access-control-allow-methods") || "")
    .toUpperCase()
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const dangerousMethods = allowedMethods.filter((method) => ["TRACE", "CONNECT"].includes(method));
  findings.push(finding(
    "http-methods",
    "Опасные HTTP-методы",
    dangerousMethods.length ? "fail" : allowedMethods.length ? "pass" : "info",
    dangerousMethods.length ? "medium" : "info",
    dangerousMethods.length
      ? `Сервер объявил опасные методы: ${dangerousMethods.join(", ")}.`
      : allowedMethods.length
        ? `Объявленные методы: ${allowedMethods.join(", ")}.`
        : "Сервер не объявил список методов; разрушительные методы не отправлялись.",
    dangerousMethods.length ? "Отключите TRACE и CONNECT на внешнем HTTP-сервере." : undefined,
  ));

  const forms = stateChangingForms(baseline.body);
  findings.push(finding(
    "csrf-forms",
    "CSRF-защита форм изменения данных",
    forms.withoutToken ? "warning" : forms.total ? "pass" : "info",
    forms.withoutToken ? "medium" : "info",
    forms.total
      ? `Найдено форм с изменяющими методами: ${forms.total}; без видимого CSRF-токена: ${forms.withoutToken}.`
      : "В публичном HTML не найдено форм с изменяющими методами.",
    forms.withoutToken
      ? "Добавьте серверный CSRF-токен и проверяйте Origin/Referer; SameSite cookie используйте как дополнительный слой."
      : undefined,
  ));

  const hasRatePolicy = [
    "ratelimit-limit",
    "ratelimit-remaining",
    "x-ratelimit-limit",
    "retry-after",
  ].some((name) => baseline.headers.has(name) || optionsProbe.headers.has(name));
  findings.push(finding(
    "auth-rate-limit",
    "Защита входа и brute-force",
    hasRatePolicy ? "pass" : forms.passwordForms ? "warning" : "info",
    forms.passwordForms && !hasRatePolicy ? "medium" : "info",
    hasRatePolicy
      ? "Сервер публикует признаки политики ограничения запросов."
      : forms.passwordForms
        ? "Найдена форма пароля, но в публичном ответе не видны заголовки rate limiting. Реальные попытки входа не выполнялись."
        : "Публичная форма входа не найдена. Реальный подбор паролей намеренно не выполняется.",
    forms.passwordForms && !hasRatePolicy
      ? "Добавьте ограничение по IP и аккаунту, экспоненциальную задержку, MFA и уведомления о подозрительных попытках."
      : undefined,
  ));

  findings.push(finding(
    "non-destructive",
    "Отсутствие разрушительных действий",
    "pass",
    "info",
    "Выполнены только GET и OPTIONS, без паролей, POST-запросов, загрузки файлов и эксплуатации.",
  ));

  return {
    reportVersion: 1,
    mode: "authorized-safe-active",
    id: crypto.randomUUID(),
    scannedAt: new Date().toISOString(),
    target: target.toString(),
    verificationUrl: new URL("/.well-known/siteguard-verification.txt", allowedOrigin).toString(),
    summary: summarize(findings),
    metrics: {
      requests: 5,
      durationMs: Date.now() - started,
      baselineStatus: baseline.status,
      reflectedStatus: reflected.status,
      inputProbeStatus: inputProbe.status,
      optionsStatus: optionsProbe.status,
    },
    findings,
    limitations: [
      "Результаты являются сигналами для ручной проверки, а не доказательством эксплуатации.",
      "SiteGuard не отправляет пароли, не перебирает учётные данные и не выполняет POST/PUT/PATCH/DELETE.",
      "Страницы за авторизацией не проверяются без отдельной тестовой интеграции.",
    ],
  };
}
