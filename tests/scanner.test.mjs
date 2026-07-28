import assert from "node:assert/strict";
import test from "node:test";

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
