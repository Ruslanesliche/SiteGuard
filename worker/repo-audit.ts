import type { AuditCheck, RepositorySummary } from "./audit-types.ts";
import { parseGitHubRepository } from "./url-safety.ts";

const GITHUB_HEADERS = {
  accept: "application/vnd.github+json",
  "user-agent": "SiteGuard/1.0 (+public-source-audit)",
  "x-github-api-version": "2022-11-28",
};
const MAX_FILES = 40;
const MAX_FILE_BYTES = 180_000;
const MAX_TOTAL_BYTES = 1_000_000;

interface GitHubRepo {
  default_branch: string;
  archived: boolean;
  fork: boolean;
}

interface GitTreeItem {
  path: string;
  type: "blob" | "tree";
  size?: number;
}

interface SourceFile {
  path: string;
  content: string;
}

function finding(
  id: string,
  title: string,
  status: AuditCheck["status"],
  severity: AuditCheck["severity"],
  evidence: string,
  recommendation: string | undefined,
  weight: number,
): AuditCheck {
  return { id, category: "source", title, status, severity, evidence, recommendation, weight };
}

async function githubJson<T>(url: string, fetcher: typeof fetch): Promise<T> {
  const response = await fetcher(url, { headers: GITHUB_HEADERS, redirect: "manual" });
  if (response.status === 404) throw new Error("Публичный GitHub-репозиторий не найден.");
  if (response.status === 403 || response.status === 429) throw new Error("GitHub временно ограничил количество проверок. Повторите позже.");
  if (!response.ok) throw new Error(`GitHub вернул HTTP ${response.status}.`);
  return response.json() as Promise<T>;
}

function priority(path: string): number {
  const lower = path.toLowerCase();
  if (lower === "package.json") return 100;
  if (/^(?:pnpm-lock\.yaml|package-lock\.json|yarn\.lock)$/u.test(lower)) return 95;
  if (lower === ".gitignore") return 94;
  if (lower === ".env" || lower.startsWith(".env.")) return 93;
  if (lower.startsWith(".github/workflows/")) return 90;
  if (/service-worker|worker\/|server\/|app\/api\/|src\/.*\.(?:js|ts|tsx|jsx)$/u.test(lower)) return 70;
  if (/\.(?:js|ts|tsx|jsx|json|ya?ml|toml)$/u.test(lower)) return 30;
  return 0;
}

function lineNumber(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function scanSecrets(files: SourceFile[]): { count: number; locations: string[] } {
  const patterns: Array<{ name: string; regex: RegExp }> = [
    { name: "Private key", regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gu },
    { name: "AWS access key", regex: /\bAKIA[0-9A-Z]{16}\b/gu },
    { name: "GitHub token", regex: /\bgh[opsu]_[A-Za-z0-9_]{30,}\b/gu },
    { name: "Stripe secret", regex: /\bsk_(?:live|test)_[A-Za-z0-9]{20,}\b/gu },
    { name: "Slack token", regex: /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/gu },
    { name: "Google API key", regex: /\bAIza[0-9A-Za-z_-]{30,}\b/gu },
    { name: "Supabase secret key", regex: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/gu },
  ];
  const locations: string[] = [];
  for (const file of files) {
    if (/\.min\.js$/iu.test(file.path)) continue;
    for (const pattern of patterns) {
      pattern.regex.lastIndex = 0;
      for (const match of file.content.matchAll(pattern.regex)) {
        locations.push(`${pattern.name}: ${file.path}:${lineNumber(file.content, match.index || 0)}`);
        if (locations.length >= 25) return { count: locations.length, locations };
      }
    }
  }
  return { count: locations.length, locations };
}

function sourceChecks(files: SourceFile[], tree: GitTreeItem[]): AuditCheck[] {
  const checks: AuditCheck[] = [];
  const paths = new Set(tree.map((item) => item.path.toLowerCase()));
  const combined = files.map((file) => `\n/* ${file.path} */\n${file.content}`).join("\n");
  const secrets = scanSecrets(files);
  checks.push(finding(
    "repo-secrets",
    "Секреты в исходном коде",
    secrets.count ? "fail" : "pass",
    "critical",
    secrets.count ? `Потенциальных секретов: ${secrets.count}. ${secrets.locations.slice(0, 6).join("; ")}` : "Высокоуверенные шаблоны секретов в проверенных файлах не обнаружены.",
    secrets.count ? "Немедленно отзовите найденные ключи, удалите их из истории Git и используйте секреты окружения." : undefined,
    12,
  ));

  const committedEnv = [...paths].filter((path) => path === ".env" || (/^\.env\./u.test(path) && path !== ".env.example"));
  checks.push(finding(
    "repo-env",
    "Файлы окружения",
    committedEnv.length ? "fail" : "pass",
    "critical",
    committedEnv.length ? `В репозитории найдены: ${committedEnv.slice(0, 8).join(", ")}` : "Закрытые .env-файлы не обнаружены.",
    committedEnv.length ? "Удалите .env из репозитория и отзовите все находившиеся в нём секреты." : undefined,
    10,
  ));

  const gitignore = files.find((file) => file.path.toLowerCase() === ".gitignore")?.content || "";
  checks.push(finding(
    "repo-gitignore",
    "Защита .env через .gitignore",
    /\.env\*?|\.env\./u.test(gitignore) ? "pass" : "warning",
    "high",
    gitignore ? "Файл .gitignore проверен." : ".gitignore не найден среди файлов репозитория.",
    "Добавьте .env, .env.* и исключение !.env.example.",
    6,
  ));

  const evalCount = (combined.match(/\beval\s*\(|new\s+Function\s*\(/gu) || []).length;
  const htmlSinkCount = (combined.match(/dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\s*\(/gu) || []).length;
  checks.push(finding(
    "repo-code-execution",
    "Опасные конструкции выполнения",
    evalCount ? "fail" : htmlSinkCount ? "warning" : "pass",
    evalCount ? "high" : "medium",
    `eval/new Function: ${evalCount}; HTML-синки: ${htmlSinkCount}.`,
    evalCount || htmlSinkCount ? "Удалите eval/new Function; валидируйте данные и используйте безопасные DOM/API React." : undefined,
    8,
  ));

  const tlsDisabled = /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|rejectUnauthorized\s*:\s*false/gu.test(combined);
  checks.push(finding(
    "repo-tls",
    "Проверка TLS в коде",
    tlsDisabled ? "fail" : "pass",
    "critical",
    tlsDisabled ? "Найдена конструкция, отключающая проверку TLS-сертификата." : "Отключение проверки TLS не обнаружено.",
    tlsDisabled ? "Удалите отключение TLS и исправьте доверие к сертификатам корректным способом." : undefined,
    10,
  ));

  const wildcardCors = /access-control-allow-origin["']?\s*[:,]\s*["']\*|cors\s*\(\s*\{\s*origin\s*:\s*["']\*/iu.test(combined);
  checks.push(finding(
    "repo-cors",
    "Широкий CORS в коде",
    wildcardCors ? "warning" : "pass",
    "high",
    wildcardCors ? "Найдена конфигурация Access-Control-Allow-Origin: *." : "Явная wildcard-конфигурация CORS не обнаружена.",
    wildcardCors ? "Разрешайте только известные origin и никогда не сочетайте wildcard с credentials." : undefined,
    6,
  ));

  const workflowFiles = files.filter((file) => file.path.toLowerCase().startsWith(".github/workflows/"));
  const dangerousWorkflow = workflowFiles.some((file) => /permissions\s*:\s*write-all|pull_request_target/iu.test(file.content));
  checks.push(finding(
    "repo-ci-permissions",
    "Права GitHub Actions",
    dangerousWorkflow ? "warning" : workflowFiles.length ? "pass" : "info",
    "high",
    dangerousWorkflow ? "В workflow найдены write-all или pull_request_target." : workflowFiles.length ? `Проверено workflow: ${workflowFiles.length}.` : "GitHub Actions не найдены.",
    dangerousWorkflow ? "Используйте минимальные permissions: contents: read и осторожно обрабатывайте pull_request_target." : undefined,
    6,
  ));

  const dependabot = paths.has(".github/dependabot.yml") || paths.has(".github/dependabot.yaml");
  checks.push(finding(
    "repo-dependency-updates",
    "Автообновление зависимостей",
    dependabot ? "pass" : "info",
    "info",
    dependabot ? "Dependabot настроен." : "Dependabot-конфигурация не найдена.",
    dependabot ? undefined : "Добавьте Dependabot или Renovate и регулярный audit в CI.",
    2,
  ));

  const serviceWorkers = files.filter((file) => /service-worker|sw\.(?:js|ts)$/iu.test(file.path));
  const unsafeCache = serviceWorkers.some((file) => /cache\.put\(event\.request|caches\.match\(event\.request/iu.test(file.content) && !/url\.origin\s*!==?\s*self\.location\.origin|\/api\//u.test(file.content));
  checks.push(finding(
    "repo-service-worker",
    "Границы Service Worker cache",
    unsafeCache ? "warning" : "pass",
    "high",
    unsafeCache ? "Service Worker кэширует запросы без очевидного ограничения same-origin/API." : serviceWorkers.length ? "В проверенных Service Worker найдены ограничения кэша или опасный паттерн отсутствует." : "Service Worker не используется.",
    unsafeCache ? "Не кэшируйте API/auth и cross-origin ответы; разрешайте только явный app shell." : undefined,
    7,
  ));

  const securityHeaders = /content-security-policy|strict-transport-security|x-content-type-options|frame-ancestors/iu.test(combined);
  checks.push(finding(
    "repo-security-headers",
    "Защитные заголовки в конфигурации",
    securityHeaders ? "pass" : "warning",
    "medium",
    securityHeaders ? "В исходном коде найдены настройки защитных заголовков." : "Настройки защитных заголовков в проверенных файлах не найдены.",
    securityHeaders ? undefined : "Настройте CSP, HSTS, nosniff, Referrer-Policy, Permissions-Policy и anti-framing на сервере/CDN.",
    5,
  ));
  return checks;
}

async function osvChecks(packageJson: SourceFile | undefined, fetcher: typeof fetch): Promise<{ checks: AuditCheck[]; dependencies: number; vulnerabilities: number }> {
  if (!packageJson) {
    return {
      checks: [finding("repo-dependencies", "Уязвимости npm-зависимостей", "info", "info", "package.json не найден.", "Для поддерживаемых проектов фиксируйте зависимости и запускайте audit в CI.", 2)],
      dependencies: 0,
      vulnerabilities: 0,
    };
  }
  let parsed: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    parsed = JSON.parse(packageJson.content);
  } catch {
    return {
      checks: [finding("repo-dependencies", "Уязвимости npm-зависимостей", "warning", "medium", "package.json не удалось разобрать.", "Исправьте JSON и подключите автоматический audit.", 4)],
      dependencies: 0,
      vulnerabilities: 0,
    };
  }
  const all = { ...(parsed.dependencies || {}), ...(parsed.devDependencies || {}) };
  const exact = Object.entries(all)
    .map(([name, version]) => [name, String(version).replace(/^[~^=v\s]+/u, "")] as const)
    .filter(([, version]) => /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u.test(version))
    .slice(0, 100);
  if (!exact.length) {
    return {
      checks: [finding("repo-dependencies", "Уязвимости npm-зависимостей", "info", "info", `Зависимостей: ${Object.keys(all).length}; точные версии для OSV не найдены.`, "Используйте lock-файл и audit в CI.", 2)],
      dependencies: Object.keys(all).length,
      vulnerabilities: 0,
    };
  }
  try {
    const response = await fetcher("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify({
        queries: exact.map(([name, version]) => ({ package: { ecosystem: "npm", name }, version })),
      }),
      redirect: "manual",
    });
    if (!response.ok) throw new Error("osv_unavailable");
    const payload = await response.json() as { results?: Array<{ vulns?: Array<{ id: string }> }> };
    const vulnerabilities = (payload.results || []).reduce((sum, item) => sum + (item.vulns?.length || 0), 0);
    return {
      checks: [finding(
        "repo-dependencies",
        "Уязвимости npm-зависимостей",
        vulnerabilities ? "fail" : "pass",
        vulnerabilities ? "high" : "medium",
        `OSV проверил точных версий: ${exact.length}; найдено записей об уязвимостях: ${vulnerabilities}.`,
        vulnerabilities ? "Обновите зависимости, проверьте changelog и повторно запустите тесты/audit." : undefined,
        9,
      )],
      dependencies: Object.keys(all).length,
      vulnerabilities,
    };
  } catch {
    return {
      checks: [finding("repo-dependencies", "Уязвимости npm-зависимостей", "info", "info", "OSV временно недоступен; статическая проверка продолжена.", "Запустите npm/pnpm audit локально или в CI.", 2)],
      dependencies: Object.keys(all).length,
      vulnerabilities: 0,
    };
  }
}

export async function auditRepository(input: string, fetcher: typeof fetch = fetch): Promise<RepositorySummary | undefined> {
  const parsed = parseGitHubRepository(input);
  if (!parsed) return undefined;
  try {
    const repo = await githubJson<GitHubRepo>(`https://api.github.com/repos/${parsed.owner}/${parsed.repo}`, fetcher);
    const commitResponse = await githubJson<{ sha: string; commit: { tree: { sha: string } } }>(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/commits/${encodeURIComponent(repo.default_branch)}`,
      fetcher,
    );
    const treeResponse = await githubJson<{ sha: string; tree: GitTreeItem[]; truncated?: boolean }>(
      `https://api.github.com/repos/${parsed.owner}/${parsed.repo}/git/trees/${commitResponse.commit.tree.sha}?recursive=1`,
      fetcher,
    );
    const candidates = treeResponse.tree
      .filter((item) => item.type === "blob" && priority(item.path) > 0 && (item.size || 0) <= MAX_FILE_BYTES)
      .sort((a, b) => priority(b.path) - priority(a.path) || a.path.localeCompare(b.path))
      .slice(0, MAX_FILES);
    const selected: GitTreeItem[] = [];
    let selectedBytes = 0;
    for (const item of candidates) {
      if (selectedBytes + (item.size || 0) > MAX_TOTAL_BYTES) continue;
      selected.push(item);
      selectedBytes += item.size || 0;
    }

    const files = (await Promise.all(selected.map(async (item): Promise<SourceFile | null> => {
      const rawPath = item.path.split("/").map(encodeURIComponent).join("/");
      const response = await fetcher(
        `https://raw.githubusercontent.com/${parsed.owner}/${parsed.repo}/${commitResponse.sha}/${rawPath}`,
        { headers: { "user-agent": GITHUB_HEADERS["user-agent"] }, redirect: "manual" },
      );
      if (!response.ok) return null;
      const content = await response.text();
      return { path: item.path, content };
    }))).filter((file): file is SourceFile => Boolean(file));

    const baseChecks = sourceChecks(files, treeResponse.tree);
    const dependencies = await osvChecks(files.find((file) => file.path.toLowerCase() === "package.json"), fetcher);
    if (treeResponse.truncated) {
      baseChecks.push(finding("repo-tree-limit", "Полнота дерева GitHub", "info", "info", "GitHub вернул усечённое дерево большого репозитория.", "Дополните удалённую проверку локальным SAST и secret scanning.", 1));
    }
    return {
      repository: parsed.canonical,
      defaultBranch: repo.default_branch,
      commit: commitResponse.sha,
      filesScanned: files.length,
      dependenciesChecked: dependencies.dependencies,
      vulnerabilities: dependencies.vulnerabilities,
      checks: [...baseChecks, ...dependencies.checks],
    };
  } catch (error) {
    return {
      repository: parsed.canonical,
      defaultBranch: "",
      commit: "",
      filesScanned: 0,
      dependenciesChecked: 0,
      vulnerabilities: 0,
      checks: [],
      error: error instanceof Error ? error.message : "Не удалось проверить репозиторий.",
    };
  }
}
