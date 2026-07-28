import { assertPublicDns, normalizePublicUrl } from "./url-safety.ts";
import { isValidVerificationToken } from "./active-audit.ts";

const REQUEST_TIMEOUT_MS = 15_000;
const MAX_SPEC_BYTES = 700_000;
const MAX_API_RESPONSE_BYTES = 350_000;
const MAX_REDIRECTS = 2;
const MAX_ENDPOINTS = 250;

export type ApiEndpointMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD";

export interface ApiEndpoint {
  method: ApiEndpointMethod;
  path: string;
  summary: string;
  protected: boolean;
}

export interface ApiInventoryReport {
  reportVersion: 1;
  mode: "authorized-openapi-inventory";
  target: string;
  specificationUrl: string;
  title: string;
  apiVersion: string;
  openApiVersion: string;
  endpoints: ApiEndpoint[];
  truncated: boolean;
  requests: 2;
}

export interface AccessProbeResult {
  label: "anonymous" | "account-a-own" | "account-a-other" | "account-b-other" | "account-b-own";
  status: number;
  bytes: number;
  contentType: string;
  fingerprint: string;
}

export interface ApiAccessFinding {
  id: string;
  title: string;
  status: "pass" | "warning" | "fail" | "info";
  severity: "high" | "medium" | "low" | "info";
  evidence: string;
  recommendation?: string;
}

export interface ApiAccessReport {
  reportVersion: 1;
  mode: "authorized-api-access";
  id: string;
  scannedAt: string;
  target: string;
  specificationUrl: string;
  endpointTemplate: string;
  summary: {
    score: number;
    passed: number;
    warnings: number;
    failed: number;
    informational: number;
  };
  metrics: {
    requests: 7;
    durationMs: number;
  };
  probes: AccessProbeResult[];
  findings: ApiAccessFinding[];
  limitations: string[];
}

interface LimitedResponse {
  status: number;
  headers: Headers;
  body: string;
}

function cleanText(value: unknown, fallback: string, max = 160): string {
  if (typeof value !== "string") return fallback;
  const cleaned = value.replace(/\s+/gu, " ").trim();
  return cleaned ? cleaned.slice(0, max) : fallback;
}

async function readLimited(response: Response, limit: number): Promise<string> {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > limit) {
      await reader.cancel();
      throw new Error("Ответ API превышает безопасный лимит проверки.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

function sameOriginUrl(value: string, allowedOrigin: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value, `${allowedOrigin}/`);
  } catch {
    throw new Error("URL OpenAPI или тестового пути имеет неверный формат.");
  }
  parsed.hash = "";
  const normalized = normalizePublicUrl(parsed.toString());
  if (normalized.origin !== allowedOrigin) {
    throw new Error("OpenAPI и тестовые пути должны находиться на подтверждённом домене.");
  }
  return normalized;
}

async function safeGet(
  input: URL,
  allowedOrigin: string,
  fetcher: typeof fetch,
  options: { authorization?: string; maxBytes?: number; accept?: string } = {},
): Promise<LimitedResponse> {
  let current = new URL(input);
  for (let redirect = 0; redirect <= MAX_REDIRECTS; redirect += 1) {
    if (current.origin !== allowedOrigin) {
      throw new Error("Редирект API вышел за пределы подтверждённого домена.");
    }
    await assertPublicDns(current, fetcher);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    let response: Response;
    try {
      const headers: Record<string, string> = {
        accept: options.accept || "application/json,text/plain;q=0.7,*/*;q=0.2",
        "cache-control": "no-cache",
        "user-agent": "SiteGuard-API-Access/1.0 (+authorized-get-only-audit)",
      };
      if (options.authorization) headers.authorization = options.authorization;
      response = await fetcher(current, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers,
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new Error("API не ответил за 15 секунд.");
      }
      throw new Error("Не удалось выполнить безопасный GET-запрос к API.");
    } finally {
      clearTimeout(timeout);
    }

    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error("API вернул редирект без адреса назначения.");
      current = sameOriginUrl(new URL(location, current).toString(), allowedOrigin);
      continue;
    }
    return {
      status: response.status,
      headers: new Headers(response.headers),
      body: await readLimited(response, options.maxBytes || MAX_API_RESPONSE_BYTES),
    };
  }
  throw new Error("Слишком много редиректов во время проверки API.");
}

async function verifyOwnership(
  allowedOrigin: string,
  verificationToken: string,
  fetcher: typeof fetch,
): Promise<void> {
  if (!isValidVerificationToken(verificationToken)) {
    throw new Error("Токен подтверждения имеет неверный формат.");
  }
  const verificationUrl = new URL("/.well-known/siteguard-verification.txt", allowedOrigin);
  verificationUrl.searchParams.set("check", verificationToken.slice(-12));
  const response = await safeGet(verificationUrl, allowedOrigin, fetcher, {
    maxBytes: 2_048,
    accept: "text/plain",
  });
  if (response.status !== 200 || response.body.trim() !== verificationToken) {
    throw new Error(
      "Подтверждение владения не найдено. Опубликуйте токен без лишнего текста в /.well-known/siteguard-verification.txt.",
    );
  }
}

function parseOpenApi(body: string): {
  title: string;
  apiVersion: string;
  openApiVersion: string;
  endpoints: ApiEndpoint[];
  truncated: boolean;
} {
  let document: unknown;
  try {
    document = JSON.parse(body);
  } catch {
    throw new Error("OpenAPI-файл должен быть корректным JSON. YAML пока не поддерживается.");
  }
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new Error("OpenAPI-файл не содержит объект спецификации.");
  }
  const root = document as Record<string, unknown>;
  const openApiVersion = cleanText(root.openapi ?? root.swagger, "");
  if (!/^(?:3(?:\.\d+){1,2}|2\.0)/u.test(openApiVersion)) {
    throw new Error("Поддерживаются OpenAPI 3.x и Swagger 2.0 в формате JSON.");
  }
  if (!root.paths || typeof root.paths !== "object" || Array.isArray(root.paths)) {
    throw new Error("В OpenAPI-файле отсутствует объект paths.");
  }
  const rootSecurity = Array.isArray(root.security) && root.security.length > 0;
  const endpoints: ApiEndpoint[] = [];
  let total = 0;
  const allowedMethods = new Set<ApiEndpointMethod>(["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]);
  for (const [path, pathItem] of Object.entries(root.paths as Record<string, unknown>)) {
    if (!path.startsWith("/") || !pathItem || typeof pathItem !== "object" || Array.isArray(pathItem)) continue;
    for (const [rawMethod, rawOperation] of Object.entries(pathItem as Record<string, unknown>)) {
      const method = rawMethod.toUpperCase() as ApiEndpointMethod;
      if (!allowedMethods.has(method) || !rawOperation || typeof rawOperation !== "object" || Array.isArray(rawOperation)) {
        continue;
      }
      total += 1;
      if (endpoints.length >= MAX_ENDPOINTS) continue;
      const operation = rawOperation as Record<string, unknown>;
      const operationSecurity = Object.prototype.hasOwnProperty.call(operation, "security")
        ? Array.isArray(operation.security) && operation.security.length > 0
        : rootSecurity;
      endpoints.push({
        method,
        path: path.slice(0, 500),
        summary: cleanText(operation.summary ?? operation.operationId, "Без описания"),
        protected: operationSecurity,
      });
    }
  }
  if (!endpoints.length) throw new Error("В OpenAPI-файле не найдено поддерживаемых операций.");
  const info = root.info && typeof root.info === "object" && !Array.isArray(root.info)
    ? root.info as Record<string, unknown>
    : {};
  return {
    title: cleanText(info.title, "API без названия"),
    apiVersion: cleanText(info.version, "не указана"),
    openApiVersion,
    endpoints,
    truncated: total > endpoints.length,
  };
}

async function fetchInventoryDocument(
  target: URL,
  specificationLocation: string,
  fetcher: typeof fetch,
): Promise<{ specificationUrl: URL; parsed: ReturnType<typeof parseOpenApi> }> {
  const specificationUrl = sameOriginUrl(specificationLocation, target.origin);
  const response = await safeGet(specificationUrl, target.origin, fetcher, {
    maxBytes: MAX_SPEC_BYTES,
    accept: "application/json,application/vnd.oai.openapi+json;q=0.9,text/plain;q=0.5",
  });
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`OpenAPI-файл вернул HTTP ${response.status}.`);
  }
  return { specificationUrl, parsed: parseOpenApi(response.body) };
}

export async function importOpenApiInventory(
  input: string,
  specificationLocation: string,
  verificationToken: string,
  fetcher: typeof fetch = fetch,
): Promise<ApiInventoryReport> {
  const target = normalizePublicUrl(input);
  await verifyOwnership(target.origin, verificationToken, fetcher);
  const { specificationUrl, parsed } = await fetchInventoryDocument(target, specificationLocation, fetcher);
  return {
    reportVersion: 1,
    mode: "authorized-openapi-inventory",
    target: target.origin,
    specificationUrl: specificationUrl.toString(),
    ...parsed,
    requests: 2,
  };
}

function validBearerToken(value: unknown): value is string {
  return typeof value === "string"
    && value.length >= 12
    && value.length <= 2_048
    && !/[\r\n\0]/u.test(value);
}

function pathMatchesTemplate(template: string, actual: URL): boolean {
  const templateSegments = template.split("/").filter(Boolean);
  const actualSegments = actual.pathname.split("/").filter(Boolean);
  if (templateSegments.length !== actualSegments.length) return false;
  return templateSegments.every((segment, index) => {
    if (/^\{[^{}/]+\}$/u.test(segment)) return actualSegments[index].length > 0;
    try {
      return decodeURIComponent(segment) === decodeURIComponent(actualSegments[index]);
    } catch {
      return segment === actualSegments[index];
    }
  });
}

async function fingerprint(body: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
  return [...new Uint8Array(digest)]
    .slice(0, 8)
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

async function probe(
  label: AccessProbeResult["label"],
  url: URL,
  allowedOrigin: string,
  bearerToken: string | undefined,
  fetcher: typeof fetch,
): Promise<AccessProbeResult> {
  const response = await safeGet(url, allowedOrigin, fetcher, {
    authorization: bearerToken ? `Bearer ${bearerToken}` : undefined,
  });
  return {
    label,
    status: response.status,
    bytes: new TextEncoder().encode(response.body).byteLength,
    contentType: cleanText(response.headers.get("content-type"), "не указан", 100),
    fingerprint: await fingerprint(response.body),
  };
}

function summarize(findings: ApiAccessFinding[]) {
  const passed = findings.filter((item) => item.status === "pass").length;
  const warnings = findings.filter((item) => item.status === "warning").length;
  const failed = findings.filter((item) => item.status === "fail").length;
  const informational = findings.filter((item) => item.status === "info").length;
  const penalty = findings.reduce((sum, item) => {
    if (item.status === "pass" || item.status === "info") return sum;
    const weight = item.severity === "high" ? 35 : item.severity === "medium" ? 18 : 8;
    return sum + (item.status === "fail" ? weight : Math.ceil(weight / 2));
  }, 0);
  return { score: Math.max(0, 100 - penalty), passed, warnings, failed, informational };
}

export async function runApiAccessAudit(
  input: string,
  specificationLocation: string,
  endpointTemplate: string,
  accountAPath: string,
  accountBPath: string,
  accountAToken: string,
  accountBToken: string,
  verificationToken: string,
  fetcher: typeof fetch = fetch,
): Promise<ApiAccessReport> {
  if (!validBearerToken(accountAToken) || !validBearerToken(accountBToken)) {
    throw new Error("Тестовые токены должны содержать от 12 до 2048 символов без переносов строк.");
  }
  if (accountAToken === accountBToken) {
    throw new Error("Для проверки нужны два разных тестовых аккаунта и два разных токена.");
  }

  const target = normalizePublicUrl(input);
  const started = Date.now();
  await verifyOwnership(target.origin, verificationToken, fetcher);
  const { specificationUrl, parsed } = await fetchInventoryDocument(target, specificationLocation, fetcher);
  const selectedOperation = parsed.endpoints.find(
    (endpoint) => endpoint.method === "GET" && endpoint.path === endpointTemplate,
  );
  if (!selectedOperation) {
    throw new Error("Выбранный GET-маршрут не найден в подтверждённой OpenAPI-спецификации.");
  }

  const pathA = sameOriginUrl(accountAPath, target.origin);
  const pathB = sameOriginUrl(accountBPath, target.origin);
  if (pathA.toString() === pathB.toString()) {
    throw new Error("Укажите два разных объекта: один для аккаунта A и другой для аккаунта B.");
  }
  if (!pathMatchesTemplate(endpointTemplate, pathA) || !pathMatchesTemplate(endpointTemplate, pathB)) {
    throw new Error("Оба тестовых пути должны соответствовать выбранному шаблону OpenAPI.");
  }

  const probes = await Promise.all([
    probe("anonymous", pathA, target.origin, undefined, fetcher),
    probe("account-a-own", pathA, target.origin, accountAToken, fetcher),
    probe("account-a-other", pathB, target.origin, accountAToken, fetcher),
    probe("account-b-other", pathA, target.origin, accountBToken, fetcher),
    probe("account-b-own", pathB, target.origin, accountBToken, fetcher),
  ]);
  const byLabel = new Map(probes.map((item) => [item.label, item]));
  const anonymous = byLabel.get("anonymous")!;
  const aOwn = byLabel.get("account-a-own")!;
  const aOther = byLabel.get("account-a-other")!;
  const bOther = byLabel.get("account-b-other")!;
  const bOwn = byLabel.get("account-b-own")!;
  const isSuccess = (status: number) => status >= 200 && status < 300;
  const isDenied = (status: number) => [401, 403, 404].includes(status);

  const findings: ApiAccessFinding[] = [];
  findings.push({
    id: "anonymous-access",
    title: "Доступ без авторизации",
    status: isSuccess(anonymous.status) ? "warning" : isDenied(anonymous.status) ? "pass" : "info",
    severity: isSuccess(anonymous.status) ? "medium" : "info",
    evidence: isSuccess(anonymous.status)
      ? `Маршрут вернул HTTP ${anonymous.status} без токена. Если данные не публичные, это ошибка доступа.`
      : `Запрос без токена вернул HTTP ${anonymous.status}.`,
    recommendation: isSuccess(anonymous.status)
      ? "Убедитесь, что маршрут действительно публичный; иначе требуйте валидную сессию до чтения объекта."
      : undefined,
  });

  const ownRequestsReady = isSuccess(aOwn.status) && isSuccess(bOwn.status);
  findings.push({
    id: "test-account-baseline",
    title: "Базовый доступ тестовых аккаунтов",
    status: ownRequestsReady ? "pass" : "warning",
    severity: ownRequestsReady ? "info" : "medium",
    evidence: `A → объект A: HTTP ${aOwn.status}; B → объект B: HTTP ${bOwn.status}.`,
    recommendation: ownRequestsReady
      ? undefined
      : "Проверьте срок действия токенов и убедитесь, что каждому тестовому аккаунту принадлежит указанный объект.",
  });

  const aCrossMatches = isSuccess(aOther.status) && aOther.fingerprint === bOwn.fingerprint;
  const bCrossMatches = isSuccess(bOther.status) && bOther.fingerprint === aOwn.fingerprint;
  const crossAllowed = isSuccess(aOther.status) || isSuccess(bOther.status);
  const crossDenied = isDenied(aOther.status) && isDenied(bOther.status);
  const likelyBola = ownRequestsReady && !isSuccess(anonymous.status) && (aCrossMatches || bCrossMatches);
  findings.push({
    id: "object-level-authorization",
    title: "Изоляция объектов между аккаунтами (BOLA/IDOR)",
    status: likelyBola ? "fail" : ownRequestsReady && crossDenied ? "pass" : crossAllowed ? "warning" : "info",
    severity: likelyBola ? "high" : crossAllowed ? "medium" : "info",
    evidence: `A → объект B: HTTP ${aOther.status}; B → объект A: HTTP ${bOther.status}. ${
      likelyBola
        ? "Ответ чужого объекта совпал с ответом его владельца."
        : crossDenied
          ? "Оба перекрёстных запроса отклонены."
          : "Автоматического доказательства утечки нет; требуется просмотр правил доступа."
    }`,
    recommendation: likelyBola || crossAllowed
      ? "Проверяйте право текущего пользователя на каждый object ID на сервере; не полагайтесь на скрытие идентификатора в интерфейсе."
      : undefined,
  });

  const sameForAll = probes.every(
    (item) => item.status === anonymous.status && item.fingerprint === anonymous.fingerprint,
  );
  findings.push({
    id: "authorization-differential",
    title: "Влияние токена на ответ",
    status: sameForAll ? "warning" : "pass",
    severity: sameForAll ? "low" : "info",
    evidence: sameForAll
      ? "Все пять ответов имеют одинаковый статус и отпечаток; токены, вероятно, не влияют на этот маршрут."
      : "Статусы или безопасные отпечатки ответов различаются в зависимости от контекста доступа.",
    recommendation: sameForAll
      ? "Если маршрут должен быть закрытым, проверьте middleware авторизации и применение Bearer-токена."
      : undefined,
  });

  findings.push({
    id: "non-destructive-api-test",
    title: "Неразрушающий режим",
    status: "pass",
    severity: "info",
    evidence: "Выполнялись только семь GET-запросов: подтверждение, OpenAPI и пять сравнений доступа.",
  });

  return {
    reportVersion: 1,
    mode: "authorized-api-access",
    id: crypto.randomUUID(),
    scannedAt: new Date().toISOString(),
    target: target.origin,
    specificationUrl: specificationUrl.toString(),
    endpointTemplate,
    summary: summarize(findings),
    metrics: { requests: 7, durationMs: Date.now() - started },
    probes,
    findings,
    limitations: [
      "Это безопасная сравнительная проверка, а не доказательство эксплуатации.",
      "Используются только GET-маршруты из подтверждённой OpenAPI-спецификации.",
      "Тестовые Bearer-токены используются только во время запроса, не возвращаются в отчёте и не сохраняются.",
      "Проверяйте только специально созданные тестовые аккаунты без реальных персональных данных.",
    ],
  };
}
