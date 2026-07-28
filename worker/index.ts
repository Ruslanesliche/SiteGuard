/** Cloudflare Worker entry point for SiteGuard. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";
import { isValidVerificationToken, runActiveAudit } from "./active-audit.ts";
import { scanTarget } from "./scanner.ts";

interface Env {
  ASSETS: Fetcher;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const MAX_REQUEST_BYTES = 4_096;
const RATE_WINDOW_MS = 10 * 60 * 1_000;
const RATE_LIMIT = 12;
const MAX_RATE_BUCKETS = 5_000;
const rateBuckets = new Map<string, { count: number; resetAt: number }>();

const PAGE_SECURITY_HEADERS: Record<string, string> = {
  "content-security-policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; media-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; manifest-src 'self'; upgrade-insecure-requests",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "origin-agent-cluster": "?1",
  "permissions-policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  "referrer-policy": "no-referrer",
  "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
};

const API_SECURITY_HEADERS: Record<string, string> = {
  ...PAGE_SECURITY_HEADERS,
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  "cache-control": "no-store",
};

function json(data: unknown, status = 200, extra: Record<string, string> = {}): Response {
  return Response.json(data, {
    status,
    headers: {
      ...API_SECURITY_HEADERS,
      "content-type": "application/json; charset=utf-8",
      ...extra,
    },
  });
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return !origin || origin === new URL(request.url).origin;
}

function rateLimit(request: Request): number {
  const key = request.headers.get("cf-connecting-ip") || "local";
  const now = Date.now();
  if (rateBuckets.size >= MAX_RATE_BUCKETS) {
    for (const [bucketKey, value] of rateBuckets) {
      if (value.resetAt <= now) rateBuckets.delete(bucketKey);
    }
    if (rateBuckets.size >= MAX_RATE_BUCKETS) rateBuckets.clear();
  }
  const bucket = rateBuckets.get(key);
  if (!bucket || bucket.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + RATE_WINDOW_MS });
    return 0;
  }
  bucket.count += 1;
  if (bucket.count <= RATE_LIMIT) return 0;
  return Math.max(1, Math.ceil((bucket.resetAt - now) / 1_000));
}

function safeScanError(error: unknown): string {
  if (!(error instanceof Error)) return "Не удалось выполнить проверку.";
  const message = error.message.trim();
  const expected =
    /^(Введите|Используйте|Разрешены|Локальные|Внутренние|Не удалось|Сайт|Слишком|URL|GitHub|Репозиторий|DNS|Редирект|Ответ)/u;
  return expected.test(message) && message.length <= 240
    ? message
    : "Не удалось выполнить проверку. Проверьте URL и повторите попытку.";
}

async function handleScan(request: Request): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405, { allow: "POST" });
  if (!sameOrigin(request)) return json({ error: "origin_mismatch", message: "Запрос отклонён." }, 403);
  if (!(request.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) {
    return json({ error: "unsupported_media_type", message: "Ожидается JSON." }, 415);
  }
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_REQUEST_BYTES) return json({ error: "request_too_large", message: "Запрос слишком большой." }, 413);
  const retryAfter = rateLimit(request);
  if (retryAfter) return json({ error: "rate_limited", message: "Слишком много проверок. Повторите позже." }, 429, { "retry-after": String(retryAfter) });

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_REQUEST_BYTES) {
    return json({ error: "request_too_large", message: "Запрос слишком большой." }, 413);
  }
  let body: { url?: unknown; repository?: unknown };
  try {
    body = JSON.parse(raw) as { url?: unknown; repository?: unknown };
  } catch {
    return json({ error: "invalid_json", message: "Некорректный JSON." }, 400);
  }
  if (typeof body.url !== "string" || body.url.trim().length < 4) {
    return json({ error: "invalid_url", message: "Введите URL сайта." }, 400);
  }
  if (body.repository != null && typeof body.repository !== "string") {
    return json({ error: "invalid_repository", message: "Некорректная ссылка на репозиторий." }, 400);
  }
  try {
    const report = await scanTarget({
      url: body.url,
      repository: typeof body.repository === "string" ? body.repository : undefined,
    });
    return json(report);
  } catch (error) {
    return json({
      error: "scan_failed",
      message: safeScanError(error),
    }, 422);
  }
}

function safeActiveError(error: unknown): string {
  if (!(error instanceof Error)) return "Не удалось выполнить активную проверку.";
  const message = error.message.trim();
  const expected = /^(Введите|Токен|Подтверждение|Опубликуйте|Ответ|Редирект|Сайт|Не удалось|Слишком много|DNS|Домен|Локальные|Частные|URL)/u;
  return expected.test(message) && message.length <= 320
    ? message
    : "Не удалось выполнить активную проверку. Проверьте URL и файл подтверждения.";
}

async function handleActiveScan(request: Request): Promise<Response> {
  if (request.method !== "POST") return json({ error: "method_not_allowed" }, 405, { allow: "POST" });
  if (!sameOrigin(request)) return json({ error: "origin_mismatch", message: "Запрос отклонён." }, 403);
  if (!(request.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) {
    return json({ error: "unsupported_media_type", message: "Ожидается JSON." }, 415);
  }
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > MAX_REQUEST_BYTES) {
    return json({ error: "request_too_large", message: "Запрос слишком большой." }, 413);
  }
  const retryAfter = rateLimit(request);
  if (retryAfter) {
    return json(
      { error: "rate_limited", message: "Слишком много активных проверок. Повторите позже." },
      429,
      { "retry-after": String(retryAfter) },
    );
  }

  const raw = await request.text();
  if (new TextEncoder().encode(raw).byteLength > MAX_REQUEST_BYTES) {
    return json({ error: "request_too_large", message: "Запрос слишком большой." }, 413);
  }
  let body: { url?: unknown; verificationToken?: unknown; confirmed?: unknown };
  try {
    body = JSON.parse(raw) as { url?: unknown; verificationToken?: unknown; confirmed?: unknown };
  } catch {
    return json({ error: "invalid_json", message: "Некорректный JSON." }, 400);
  }
  if (typeof body.url !== "string" || body.url.trim().length < 4) {
    return json({ error: "invalid_url", message: "Введите URL сайта." }, 400);
  }
  if (!isValidVerificationToken(body.verificationToken)) {
    return json({ error: "invalid_verification_token", message: "Токен подтверждения имеет неверный формат." }, 400);
  }
  if (body.confirmed !== true) {
    return json({
      error: "ownership_confirmation_required",
      message: "Подтвердите, что вы владеете сайтом или имеете разрешение на проверку.",
    }, 400);
  }

  try {
    return json(await runActiveAudit(body.url, body.verificationToken));
  } catch (error) {
    return json({ error: "active_scan_failed", message: safeActiveError(error) }, 422);
  }
}

function secure(response: Response, api = false): Response {
  const secured = new Response(response.body, response);
  const headers = api ? API_SECURITY_HEADERS : PAGE_SECURITY_HEADERS;
  for (const [name, value] of Object.entries(headers)) secured.headers.set(name, value);
  return secured;
}

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/scan") return handleScan(request);
    if (url.pathname === "/api/active-scan") return handleActiveScan(request);
    if (url.pathname === "/api/health") return json({ ok: true, service: "SiteGuard", version: 1 });

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      const imageResponse = await handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
      return secure(imageResponse);
    }

    return secure(await handler.fetch(request, env, ctx));
  },
};

export default worker;
