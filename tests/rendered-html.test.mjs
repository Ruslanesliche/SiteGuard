import assert from "node:assert/strict";
import test from "node:test";

async function render(path = "/", options = {}) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${Math.random()}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request(`https://siteguard.example${path}`, options),
    {
      ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
    },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders the finished SiteGuard application", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.equal(response.headers.get("strict-transport-security"), "max-age=63072000; includeSubDomains; preload");

  const html = await response.text();
  assert.match(html, /<title>SiteGuard — аудит безопасности сайтов<\/title>/i);
  assert.match(html, /Найдите слабые места/);
  assert.match(html, /Проверить сайт/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|Your site is taking shape/i);
});

test("scan API rejects unauthentic origins and invalid media types", async () => {
  const wrongOrigin = await render("/api/scan", {
    method: "POST",
    headers: { origin: "https://attacker.example", "content-type": "application/json" },
    body: JSON.stringify({ url: "https://example.com" }),
  });
  assert.equal(wrongOrigin.status, 403);
  assert.equal(wrongOrigin.headers.get("cache-control"), "no-store");

  const wrongType = await render("/api/scan", {
    method: "POST",
    body: "url=https://example.com",
  });
  assert.equal(wrongType.status, 415);
});

test("health endpoint is protected and does not cache", async () => {
  const response = await render("/api/health");
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { ok: true, service: "SiteGuard", version: 1 });
});
