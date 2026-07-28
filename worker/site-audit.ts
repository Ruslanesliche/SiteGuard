import type { AuditCheck, FetchResult, SiteMetrics } from "./audit-types.ts";
import { assertPublicDns, normalizePublicUrl } from "./url-safety.ts";

const MAX_HTML_BYTES = 1_000_000;
const MAX_REDIRECTS = 5;
const REQUEST_TIMEOUT_MS = 12_000;
const TRACKER_HOSTS = [
  "google-analytics.com",
  "googletagmanager.com",
  "facebook.net",
  "hotjar.com",
  "clarity.ms",
  "yandex.ru",
  "mc.yandex.ru",
  "doubleclick.net",
];

function check(
  id: string,
  category: string,
  title: string,
  status: AuditCheck["status"],
  severity: AuditCheck["severity"],
  evidence: string,
  recommendation: string | undefined,
  weight: number,
): AuditCheck {
  return { id, category, title, status, severity, evidence, recommendation, weight };
}

async function readLimited(response: Response, limit = MAX_HTML_BYTES): Promise<{ text: string; bytes: number }> {
  if (!response.body) return { text: "", bytes: 0 };
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
      throw new Error("HTML-страница превышает безопасный лимит 1 МБ.");
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return { text, bytes };
}

async function fetchWithTimeout(url: URL, fetcher: typeof fetch): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    return await fetcher(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.2",
        "user-agent": "SiteGuard/1.0 (+passive-security-audit)",
      },
    });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") throw new Error("Сайт не ответил за 12 секунд.");
    throw new Error("Не удалось подключиться к сайту.");
  } finally {
    clearTimeout(timeout);
  }
}

export async function fetchPublicSite(input: string, fetcher: typeof fetch = fetch): Promise<FetchResult> {
  const requestedUrl = normalizePublicUrl(input);
  let current = new URL(requestedUrl);
  const redirects: FetchResult["redirects"] = [];
  const started = Date.now();

  for (let index = 0; index <= MAX_REDIRECTS; index += 1) {
    await assertPublicDns(current, fetcher);
    const response = await fetchWithTimeout(current, fetcher);
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location) throw new Error("Сайт вернул перенаправление без адреса назначения.");
      redirects.push({ url: current.toString(), status: response.status });
      if (redirects.length > MAX_REDIRECTS) throw new Error("Слишком много перенаправлений.");
      current = normalizePublicUrl(new URL(location, current).toString());
      continue;
    }

    const contentType = response.headers.get("content-type") || "";
    const readable = /text\/html|application\/xhtml\+xml/iu.test(contentType);
    const { text: html, bytes } = readable ? await readLimited(response) : { text: "", bytes: 0 };
    return {
      requestedUrl,
      finalUrl: current,
      response,
      html,
      bytes,
      durationMs: Date.now() - started,
      redirects,
    };
  }
  throw new Error("Слишком много перенаправлений.");
}

function headerChecks(result: FetchResult): AuditCheck[] {
  const { response, finalUrl } = result;
  const headers = response.headers;
  const checks: AuditCheck[] = [];
  const csp = headers.get("content-security-policy") || "";
  const hsts = headers.get("strict-transport-security") || "";
  const frameProtected = /frame-ancestors/iu.test(csp) || Boolean(headers.get("x-frame-options"));
  const referrer = (headers.get("referrer-policy") || "").toLowerCase();
  const robustReferrer = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"].some((value) => referrer.includes(value));

  checks.push(check(
    "https",
    "transport",
    "HTTPS-соединение",
    finalUrl.protocol === "https:" ? "pass" : "fail",
    "critical",
    finalUrl.protocol === "https:" ? "Финальный адрес использует HTTPS." : "Финальный адрес доступен по незашифрованному HTTP.",
    finalUrl.protocol === "https:" ? undefined : "Настройте TLS-сертификат и перенаправляйте весь HTTP-трафик на HTTPS.",
    12,
  ));
  checks.push(check(
    "hsts",
    "transport",
    "HTTP Strict Transport Security",
    finalUrl.protocol !== "https:" ? "fail" : hsts ? (/max-age=(?:\d{8,})/iu.test(hsts) ? "pass" : "warning") : "fail",
    "high",
    hsts ? `HSTS: ${hsts.slice(0, 180)}` : "Заголовок Strict-Transport-Security отсутствует.",
    hsts ? "Используйте max-age не менее 15552000; после проверки добавьте includeSubDomains." : "Добавьте HSTS на HTTPS-ответы.",
    8,
  ));
  checks.push(check(
    "csp",
    "headers",
    "Content Security Policy",
    !csp ? "fail" : /unsafe-eval|\*\s*(?:;|$)/iu.test(csp) ? "warning" : "pass",
    "high",
    csp ? csp.slice(0, 260) : "Content-Security-Policy отсутствует.",
    !csp ? "Добавьте CSP с default-src 'self', object-src 'none', base-uri 'none' и frame-ancestors." : "Уберите unsafe-eval и широкие источники; переходите к nonce/hash для скриптов.",
    10,
  ));
  checks.push(check(
    "anti-framing",
    "headers",
    "Защита от clickjacking",
    frameProtected ? "pass" : "fail",
    "high",
    frameProtected ? "Найдена frame-ancestors или X-Frame-Options." : "Защита от встраивания во фрейм не обнаружена.",
    frameProtected ? undefined : "Добавьте CSP frame-ancestors 'none' (или разрешённые домены) и X-Frame-Options: DENY.",
    7,
  ));
  checks.push(check(
    "nosniff",
    "headers",
    "Запрет MIME-sniffing",
    headers.get("x-content-type-options")?.toLowerCase() === "nosniff" ? "pass" : "fail",
    "medium",
    headers.get("x-content-type-options") || "X-Content-Type-Options отсутствует.",
    "Добавьте X-Content-Type-Options: nosniff.",
    5,
  ));
  checks.push(check(
    "referrer-policy",
    "headers",
    "Политика Referrer",
    robustReferrer ? "pass" : referrer ? "warning" : "fail",
    "medium",
    referrer || "Referrer-Policy отсутствует.",
    "Используйте no-referrer или strict-origin-when-cross-origin.",
    4,
  ));
  checks.push(check(
    "permissions-policy",
    "headers",
    "Permissions Policy",
    headers.has("permissions-policy") ? "pass" : "warning",
    "low",
    headers.get("permissions-policy") || "Permissions-Policy отсутствует.",
    "Явно отключите неиспользуемые camera, microphone, geolocation, payment и usb.",
    3,
  ));
  checks.push(check(
    "coop",
    "headers",
    "Cross-Origin Opener Policy",
    headers.get("cross-origin-opener-policy") === "same-origin" ? "pass" : "warning",
    "low",
    headers.get("cross-origin-opener-policy") || "COOP не задан.",
    "Для обычного приложения рассмотрите Cross-Origin-Opener-Policy: same-origin.",
    2,
  ));

  const allowOrigin = headers.get("access-control-allow-origin");
  const allowCredentials = headers.get("access-control-allow-credentials");
  checks.push(check(
    "cors",
    "headers",
    "Настройки CORS",
    allowOrigin === "*" && allowCredentials === "true" ? "fail" : allowOrigin === "*" ? "warning" : "pass",
    allowOrigin === "*" && allowCredentials === "true" ? "critical" : "medium",
    allowOrigin ? `Access-Control-Allow-Origin: ${allowOrigin}` : "Широкий CORS на HTML-ответе не обнаружен.",
    allowOrigin === "*" ? "Не используйте wildcard для приватных данных; разрешайте только доверенные origin." : undefined,
    6,
  ));

  const poweredBy = headers.get("x-powered-by");
  const server = headers.get("server");
  checks.push(check(
    "server-disclosure",
    "headers",
    "Раскрытие технологий",
    poweredBy ? "warning" : "pass",
    "low",
    poweredBy ? `X-Powered-By: ${poweredBy}` : server ? `Точный фреймворк не раскрыт; Server: ${server.slice(0, 80)}` : "Технологические заголовки не раскрывают фреймворк.",
    poweredBy ? "Удалите X-Powered-By и подробные версии серверного ПО." : undefined,
    2,
  ));

  const cacheControl = headers.get("cache-control") || "";
  const setCookie = headers.get("set-cookie") || "";
  checks.push(check(
    "private-cache",
    "headers",
    "Кэширование персональных ответов",
    setCookie && /public|s-maxage/iu.test(cacheControl) ? "fail" : "pass",
    "high",
    setCookie ? `Ответ устанавливает cookie; Cache-Control: ${cacheControl || "не задан"}` : "На основном ответе нет сочетания cookie с публичным кэшем.",
    setCookie && /public|s-maxage/iu.test(cacheControl) ? "Используйте private, no-store для персональных страниц." : undefined,
    6,
  ));
  return checks;
}

interface TagInfo {
  raw: string;
  attrs: Record<string, string>;
}

function tags(html: string, name: string): TagInfo[] {
  const expression = new RegExp(`<${name}\\b([^>]*)>`, "giu");
  return [...html.matchAll(expression)].slice(0, 2_000).map((match) => {
    const attrs: Record<string, string> = {};
    const source = match[1] || "";
    for (const attr of source.matchAll(/([:\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/gu)) {
      attrs[attr[1].toLowerCase()] = attr[2] ?? attr[3] ?? attr[4] ?? "";
    }
    return { raw: match[0], attrs };
  });
}

function resolveResource(value: string, base: URL): URL | null {
  if (!value || /^(?:data|blob|mailto|tel|javascript):/iu.test(value)) return null;
  try {
    return new URL(value, base);
  } catch {
    return null;
  }
}

function htmlChecks(result: FetchResult): { checks: AuditCheck[]; metrics: Omit<SiteMetrics, "responseTimeMs" | "htmlBytes" | "statusCode" | "redirects">; technologies: string[] } {
  const { html, finalUrl } = result;
  const checks: AuditCheck[] = [];
  if (!html) {
    checks.push(check("html-content", "application", "HTML-документ", "warning", "medium", "Основной ответ не является HTML или не содержит читаемого документа.", "Проверьте Content-Type и доступность главной страницы.", 5));
    return {
      checks,
      metrics: { scripts: 0, thirdPartyScripts: 0, images: 0, stylesheets: 0, forms: 0, externalOrigins: 0 },
      technologies: [],
    };
  }

  const scripts = tags(html, "script");
  const images = tags(html, "img");
  const links = tags(html, "link");
  const forms = tags(html, "form");
  const iframes = tags(html, "iframe");
  const anchors = tags(html, "a");
  const inputs = tags(html, "input");
  const resourceUrls = [
    ...scripts.map((item) => item.attrs.src),
    ...images.map((item) => item.attrs.src),
    ...links.map((item) => item.attrs.href),
    ...iframes.map((item) => item.attrs.src),
  ].map((value) => resolveResource(value, finalUrl)).filter((value): value is URL => Boolean(value));
  const externalOrigins = new Set(resourceUrls.filter((url) => url.origin !== finalUrl.origin).map((url) => url.origin));
  const thirdPartyScripts = scripts.filter((item) => {
    const url = resolveResource(item.attrs.src, finalUrl);
    return url && url.origin !== finalUrl.origin;
  });
  const insecureResources = resourceUrls.filter((url) => finalUrl.protocol === "https:" && url.protocol === "http:");
  const scriptsWithoutSri = thirdPartyScripts.filter((item) => !item.attrs.integrity);
  const inlineHandlers = (html.match(/\son[a-z]+\s*=/giu) || []).length;
  const javascriptUrls = (html.match(/(?:href|src)\s*=\s*["']\s*javascript:/giu) || []).length;
  const dangerousSinks = (html.match(/\b(?:eval\s*\(|new\s+Function\s*\(|document\.write\s*\(|\.innerHTML\s*=)/gu) || []).length;
  const blankWithoutRel = anchors.filter((item) => item.attrs.target === "_blank" && !/\bnoopener\b/iu.test(item.attrs.rel || ""));
  const unsandboxedFrames = iframes.filter((item) => !("sandbox" in item.attrs));
  const passwordInputs = inputs.filter((item) => item.attrs.type?.toLowerCase() === "password");
  const httpForms = forms.filter((item) => resolveResource(item.attrs.action, finalUrl)?.protocol === "http:");

  checks.push(check(
    "status-code",
    "application",
    "HTTP-статус главной страницы",
    result.response.status >= 200 && result.response.status < 400 ? "pass" : result.response.status >= 500 ? "fail" : "warning",
    result.response.status >= 500 ? "high" : "medium",
    `Сервер вернул HTTP ${result.response.status}.`,
    result.response.ok ? undefined : "Исправьте ошибки маршрутизации и ответы 4xx/5xx основной страницы.",
    6,
  ));
  checks.push(check(
    "mixed-content",
    "application",
    "Смешанный контент",
    insecureResources.length ? "fail" : "pass",
    "high",
    insecureResources.length ? `Найдено HTTP-ресурсов на HTTPS-странице: ${insecureResources.length}.` : "HTTP-ресурсы на HTTPS-странице не обнаружены.",
    insecureResources.length ? "Загружайте все скрипты, стили, изображения и iframe только по HTTPS." : undefined,
    8,
  ));
  checks.push(check(
    "third-party-sri",
    "supply-chain",
    "Целостность сторонних скриптов",
    scriptsWithoutSri.length ? "warning" : "pass",
    "high",
    thirdPartyScripts.length
      ? `${thirdPartyScripts.length} сторонних скриптов; без integrity: ${scriptsWithoutSri.length}.`
      : "Сторонние скрипты не обнаружены.",
    scriptsWithoutSri.length ? "Самостоятельно размещайте зависимости или добавьте integrity и crossorigin." : undefined,
    7,
  ));
  checks.push(check(
    "inline-execution",
    "application",
    "Небезопасное выполнение JavaScript",
    javascriptUrls || dangerousSinks ? "fail" : inlineHandlers ? "warning" : "pass",
    javascriptUrls || dangerousSinks ? "high" : "medium",
    `Inline-обработчики: ${inlineHandlers}; javascript: URL: ${javascriptUrls}; опасные DOM-синки: ${dangerousSinks}.`,
    javascriptUrls || dangerousSinks || inlineHandlers ? "Удалите javascript: URL, inline-обработчики, eval/document.write и безопасно формируйте DOM через textContent." : undefined,
    8,
  ));
  checks.push(check(
    "forms-transport",
    "application",
    "Безопасность форм",
    httpForms.length || (passwordInputs.length && finalUrl.protocol !== "https:") ? "fail" : "pass",
    "critical",
    `Форм: ${forms.length}; password-полей: ${passwordInputs.length}; HTTP action: ${httpForms.length}.`,
    httpForms.length ? "Отправляйте формы только на HTTPS same-origin адреса." : undefined,
    8,
  ));
  checks.push(check(
    "blank-links",
    "application",
    "Защита внешних вкладок",
    blankWithoutRel.length ? "warning" : "pass",
    "low",
    blankWithoutRel.length ? `Ссылок target=_blank без noopener: ${blankWithoutRel.length}.` : "Опасные target=_blank ссылки не обнаружены.",
    blankWithoutRel.length ? "Добавьте rel=\"noopener noreferrer\"." : undefined,
    2,
  ));
  checks.push(check(
    "iframe-sandbox",
    "application",
    "Изоляция iframe",
    unsandboxedFrames.length ? "warning" : "pass",
    "medium",
    iframes.length ? `iframe: ${iframes.length}; без sandbox: ${unsandboxedFrames.length}.` : "iframe не используются.",
    unsandboxedFrames.length ? "Добавьте минимально необходимый sandbox и ограничьте frame-src в CSP." : undefined,
    4,
  ));

  const title = html.match(/<title[^>]*>([\s\S]*?)<\/title>/iu)?.[1]?.replace(/<[^>]+>/gu, "").trim() || "";
  const lang = html.match(/<html[^>]*\blang\s*=\s*["']([^"']+)/iu)?.[1] || "";
  const description = html.match(/<meta[^>]+\bname\s*=\s*["']description["'][^>]+\bcontent\s*=\s*["']([^"']*)/iu)?.[1]
    || html.match(/<meta[^>]+\bcontent\s*=\s*["']([^"']*)["'][^>]+\bname\s*=\s*["']description/iu)?.[1]
    || "";
  const h1Count = (html.match(/<h1\b/giu) || []).length;
  const missingAlt = images.filter((item) => !("alt" in item.attrs)).length;
  const viewport = /<meta[^>]+\bname\s*=\s*["']viewport["']/iu.test(html);
  const manifest = links.some((item) => item.attrs.rel?.toLowerCase().split(/\s+/u).includes("manifest"));
  const serviceWorker = /navigator\.serviceWorker|serviceWorker\.register/iu.test(html);
  const securityTxt = /security\.txt/iu.test(html);

  checks.push(check("page-title", "quality", "Заголовок страницы", title.length >= 8 && title.length <= 70 ? "pass" : "warning", "low", title ? `Title: ${title.slice(0, 100)}` : "Тег title отсутствует.", "Добавьте уникальный title длиной примерно 8–70 символов.", 2));
  checks.push(check("page-description", "quality", "Meta description", description.length >= 50 && description.length <= 180 ? "pass" : "warning", "low", description ? `Описание: ${description.slice(0, 180)}` : "Meta description отсутствует.", "Добавьте понятное описание страницы.", 2));
  checks.push(check("document-lang", "accessibility", "Язык документа", lang ? "pass" : "warning", "medium", lang ? `lang=\"${lang}\"` : "Атрибут lang отсутствует.", "Укажите язык документа на элементе html.", 3));
  checks.push(check("heading-structure", "accessibility", "Основной заголовок", h1Count === 1 ? "pass" : "warning", "medium", `Количество h1: ${h1Count}.`, "Используйте один содержательный h1 на основной странице.", 3));
  checks.push(check("image-alt", "accessibility", "Альтернативный текст изображений", missingAlt === 0 ? "pass" : "warning", "medium", `Изображений: ${images.length}; без alt: ${missingAlt}.`, "Добавьте alt; для декоративных изображений используйте alt=\"\".", 4));
  checks.push(check("mobile-viewport", "quality", "Мобильный viewport", viewport ? "pass" : "warning", "low", viewport ? "Meta viewport найден." : "Meta viewport отсутствует.", "Добавьте width=device-width, initial-scale=1.", 2));
  checks.push(check("pwa", "quality", "PWA-готовность", manifest && serviceWorker ? "pass" : manifest || serviceWorker ? "warning" : "info", "info", `Manifest: ${manifest ? "да" : "нет"}; регистрация Service Worker: ${serviceWorker ? "да" : "нет"}.`, "Для устанавливаемого приложения добавьте manifest, иконки и безопасный Service Worker.", 1));
  checks.push(check("security-contact", "governance", "Канал сообщения об уязвимостях", securityTxt ? "pass" : "info", "info", securityTxt ? "На странице есть ссылка на security.txt." : "Ссылка на security.txt в HTML не найдена.", "Опубликуйте /.well-known/security.txt с контактами и сроком действия.", 1));

  const trackerOrigins = [...externalOrigins].filter((origin) => TRACKER_HOSTS.some((host) => new URL(origin).hostname.endsWith(host)));
  checks.push(check(
    "trackers",
    "privacy",
    "Сторонние трекеры",
    trackerOrigins.length > 2 ? "warning" : "pass",
    "medium",
    trackerOrigins.length ? `Обнаружены известные трекеры: ${trackerOrigins.join(", ").slice(0, 240)}` : "Известные трекеры в разметке не обнаружены.",
    trackerOrigins.length ? "Минимизируйте трекеры, получите согласие и документируйте передачу данных." : undefined,
    4,
  ));

  const technologies: string[] = [];
  const generator = html.match(/<meta[^>]+\bname\s*=\s*["']generator["'][^>]+\bcontent\s*=\s*["']([^"']+)/iu)?.[1];
  if (generator) technologies.push(generator.slice(0, 80));
  if (/__NEXT_DATA__|\/_next\//u.test(html)) technologies.push("Next.js");
  if (/data-reactroot|react-dom|__next_f/iu.test(html)) technologies.push("React");
  if (/wp-content|wp-includes/iu.test(html)) technologies.push("WordPress");
  if (/cdn\.shopify\.com|Shopify\.theme/iu.test(html)) technologies.push("Shopify");
  if (/cloudflare/iu.test(result.response.headers.get("server") || "")) technologies.push("Cloudflare");

  return {
    checks,
    metrics: {
      scripts: scripts.length,
      thirdPartyScripts: thirdPartyScripts.length,
      images: images.length,
      stylesheets: links.filter((item) => item.attrs.rel?.toLowerCase().includes("stylesheet")).length,
      forms: forms.length,
      externalOrigins: externalOrigins.size,
    },
    technologies: [...new Set(technologies)],
  };
}

function cookieChecks(response: Response, finalUrl: URL): AuditCheck[] {
  const headers = response.headers as Headers & { getSetCookie?: () => string[] };
  const cookies = headers.getSetCookie?.() || (headers.get("set-cookie") ? [headers.get("set-cookie") as string] : []);
  if (!cookies.length) {
    return [check("cookies", "privacy", "Флаги cookies", "pass", "medium", "Основной ответ не устанавливает cookies.", undefined, 5)];
  }
  const insecure = cookies.filter((cookie) => finalUrl.protocol === "https:" && !/;\s*secure\b/iu.test(cookie));
  const noHttpOnly = cookies.filter((cookie) => !/;\s*httponly\b/iu.test(cookie));
  const noSameSite = cookies.filter((cookie) => !/;\s*samesite=(?:lax|strict|none)\b/iu.test(cookie));
  const noneWithoutSecure = cookies.filter((cookie) => /;\s*samesite=none\b/iu.test(cookie) && !/;\s*secure\b/iu.test(cookie));
  const failed = insecure.length || noneWithoutSecure.length;
  return [check(
    "cookies",
    "privacy",
    "Флаги cookies",
    failed ? "fail" : noHttpOnly.length || noSameSite.length ? "warning" : "pass",
    failed ? "high" : "medium",
    `Cookies: ${cookies.length}; без Secure: ${insecure.length}; без HttpOnly: ${noHttpOnly.length}; без SameSite: ${noSameSite.length}.`,
    failed || noHttpOnly.length || noSameSite.length ? "Для сессионных cookies используйте Secure, HttpOnly, SameSite=Lax/Strict и префикс __Host-." : undefined,
    7,
  )];
}

export function auditSite(result: FetchResult): { checks: AuditCheck[]; metrics: SiteMetrics; technologies: string[] } {
  const html = htmlChecks(result);
  return {
    checks: [...headerChecks(result), ...cookieChecks(result.response, result.finalUrl), ...html.checks],
    metrics: {
      responseTimeMs: result.durationMs,
      htmlBytes: result.bytes,
      statusCode: result.response.status,
      redirects: result.redirects.length,
      ...html.metrics,
    },
    technologies: html.technologies,
  };
}
