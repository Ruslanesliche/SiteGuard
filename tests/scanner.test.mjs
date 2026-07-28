import assert from "node:assert/strict";
import test from "node:test";

import { isValidVerificationToken, runActiveAudit } from "../worker/active-audit.ts";
import { importOpenApiInventory, runApiAccessAudit } from "../worker/api-access-audit.ts";
import { auditSite } from "../worker/site-audit.ts";
import { isPrivateIp, normalizePublicUrl, parseGitHubRepository } from "../worker/url-safety.ts";

test("blocks private, local, credentialed and non-web targets", () => {
  for (const target of [
    "http://127.0.0.1",
    "http://2130706433",
    "http://[::1]",
    "http://169.254.169.254/latest/meta-data",
    "http://service.internal",
    "ftp://example.com",
    "https://user:password@example.com",
    "https://example.com:8443",
  ]) {
    assert.throws(() => normalizePublicUrl(target));
  }
  assert.equal(isPrivateIp("10.2.3.4"), true);
  assert.equal(isPrivateIp("93.184.216.34"), false);
  assert.equal(normalizePublicUrl("example.com").toString(), "https://example.com/");
  assert.equal(
    normalizePublicUrl("https://example.com/#/settings").toString(),
    "https://example.com/",
  );
});

test("accepts only canonical public GitHub repository URLs", () => {
  assert.deepEqual(parseGitHubRepository("github.com/openai/openai-node"), {
    owner: "openai",
    repo: "openai-node",
    canonical: "https://github.com/openai/openai-node",
  });
  assert.throws(() => parseGitHubRepository("https://gitlab.com/openai/openai-node"));
  assert.throws(() => parseGitHubRepository("https://github.com/openai/openai-node/issues"));
});

test("requires a high-entropy ownership verification token for active scans", () => {
  assert.equal(isValidVerificationToken("siteguard-verify-0123456789abcdef0123456789abcdef"), true);
  assert.equal(isValidVerificationToken("siteguard-verify-short"), false);
  assert.equal(isValidVerificationToken("0123456789abcdef0123456789abcdef"), false);
});

test("runs only verified, non-destructive active probes", async () => {
  const token = "siteguard-verify-0123456789abcdef0123456789abcdef";
  const fetcher = async (input, init = {}) => {
    const url = new URL(input);
    if (url.hostname === "cloudflare-dns.com") {
      return Response.json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    if (url.pathname === "/.well-known/siteguard-verification.txt") {
      return new Response(token, { status: 200, headers: { "content-type": "text/plain" } });
    }
    if (init.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { allow: "GET, HEAD, OPTIONS" },
      });
    }
    const html = `
      <!doctype html><form method="post">
        <input type="hidden" name="csrf_token" value="safe">
        <input type="password" name="password">
      </form>`;
    return new Response(html, {
      status: 200,
      headers: {
        "content-type": "text/html",
        "ratelimit-limit": "20",
      },
    });
  };

  const report = await runActiveAudit("https://example.com/login", token, fetcher);
  assert.equal(report.mode, "authorized-safe-active");
  assert.equal(report.metrics.requests, 5);
  assert.equal(report.findings.find((item) => item.id === "ownership")?.status, "pass");
  assert.equal(report.findings.find((item) => item.id === "sql-error-signal")?.status, "pass");
  assert.equal(report.findings.find((item) => item.id === "csrf-forms")?.status, "pass");
  assert.equal(report.findings.find((item) => item.id === "auth-rate-limit")?.status, "pass");
});

test("imports a same-origin OpenAPI inventory after ownership verification", async () => {
  const token = "siteguard-verify-0123456789abcdef0123456789abcdef";
  const specification = {
    openapi: "3.1.0",
    info: { title: "Accounts API", version: "2.4.0" },
    security: [{ bearerAuth: [] }],
    paths: {
      "/api/accounts/{id}": {
        get: { summary: "Account details" },
        patch: { summary: "Update account" },
      },
      "/health": {
        get: { summary: "Health", security: [] },
      },
    },
  };
  const fetcher = async (input) => {
    const url = new URL(input);
    if (url.hostname === "cloudflare-dns.com") {
      return Response.json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    if (url.pathname === "/.well-known/siteguard-verification.txt") {
      return new Response(token, { status: 200, headers: { "content-type": "text/plain" } });
    }
    if (url.pathname === "/openapi.json") {
      return Response.json(specification);
    }
    return new Response("Not found", { status: 404 });
  };

  const report = await importOpenApiInventory("https://example.com", "/openapi.json", token, fetcher);
  assert.equal(report.title, "Accounts API");
  assert.equal(report.requests, 2);
  assert.equal(report.endpoints.length, 3);
  assert.equal(report.endpoints.find((item) => item.path === "/health")?.protected, false);
  assert.equal(report.endpoints.find((item) => item.path === "/api/accounts/{id}")?.protected, true);
});

test("compares object access with two test accounts without exposing tokens", async () => {
  const verificationToken = "siteguard-verify-0123456789abcdef0123456789abcdef";
  const accountAToken = "test-account-a-token-123";
  const accountBToken = "test-account-b-token-456";
  const specification = {
    openapi: "3.0.3",
    info: { title: "Objects API", version: "1" },
    paths: {
      "/api/objects/{id}": {
        get: { summary: "Read object", security: [{ bearerAuth: [] }] },
      },
    },
  };
  const fetcher = async (input, init = {}) => {
    const url = new URL(input);
    if (url.hostname === "cloudflare-dns.com") {
      return Response.json({ Status: 0, Answer: [{ type: 1, data: "93.184.216.34" }] });
    }
    if (url.pathname === "/.well-known/siteguard-verification.txt") {
      return new Response(verificationToken, { status: 200 });
    }
    if (url.pathname === "/openapi.json") return Response.json(specification);
    const authorization = new Headers(init.headers).get("authorization");
    if (!authorization) return Response.json({ error: "unauthorized" }, { status: 401 });
    if (url.pathname === "/api/objects/101" && authorization === `Bearer ${accountAToken}`) {
      return Response.json({ id: 101, owner: "a" });
    }
    if (url.pathname === "/api/objects/202" && authorization === `Bearer ${accountBToken}`) {
      return Response.json({ id: 202, owner: "b" });
    }
    return Response.json({ error: "forbidden" }, { status: 403 });
  };

  const report = await runApiAccessAudit(
    "https://example.com",
    "/openapi.json",
    "/api/objects/{id}",
    "/api/objects/101",
    "/api/objects/202",
    accountAToken,
    accountBToken,
    verificationToken,
    fetcher,
  );
  assert.equal(report.metrics.requests, 7);
  assert.equal(report.findings.find((item) => item.id === "object-level-authorization")?.status, "pass");
  assert.equal(JSON.stringify(report).includes(accountAToken), false);
  assert.equal(JSON.stringify(report).includes(accountBToken), false);
});

test("detects missing headers, mixed content and dangerous DOM execution", () => {
  const response = new Response(`
    <!doctype html><html><head><title>X</title></head><body>
    <h1>Test</h1>
    <script src="http://cdn.example/app.js"></script>
    <a target="_blank" href="https://external.example">Open</a>
    <img src="/photo.png">
    <script>document.write(location.hash)</script>
    </body></html>
  `, { status: 200, headers: { "content-type": "text/html" } });
  const result = auditSite({
    requestedUrl: new URL("https://example.com"),
    finalUrl: new URL("https://example.com"),
    response,
    html: "<!doctype html><html><head><title>X</title></head><body><h1>Test</h1><script src=\"http://cdn.example/app.js\"></script><a target=\"_blank\" href=\"https://external.example\">Open</a><img src=\"/photo.png\"><script>document.write(location.hash)</script></body></html>",
    bytes: 300,
    durationMs: 100,
    redirects: [],
  });
  const byId = new Map(result.checks.map((item) => [item.id, item]));
  assert.equal(byId.get("csp")?.status, "fail");
  assert.equal(byId.get("mixed-content")?.status, "fail");
  assert.equal(byId.get("inline-execution")?.status, "fail");
  assert.equal(byId.get("blank-links")?.status, "warning");
  assert.equal(byId.get("image-alt")?.status, "warning");
});
