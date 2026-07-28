const BLOCKED_HOST_SUFFIXES = [
  ".localhost",
  ".local",
  ".internal",
  ".home",
  ".lan",
  ".test",
  ".invalid",
];

function ipv4Parts(hostname: string): number[] | null {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part))) return null;
  const numbers = parts.map(Number);
  return numbers.every((part) => part >= 0 && part <= 255) ? numbers : null;
}

export function isPrivateIp(value: string): boolean {
  const hostname = value.toLowerCase().replace(/^\[|\]$/gu, "");
  const ipv4 = ipv4Parts(hostname);
  if (ipv4) {
    const [a, b] = ipv4;
    return a === 0
      || a === 10
      || a === 127
      || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 0)
      || (a === 192 && b === 168)
      || (a === 198 && (b === 18 || b === 19))
      || a >= 224;
  }

  if (!hostname.includes(":")) return false;
  const compact = hostname.replace(/^0+/u, "");
  return compact === "::1"
    || compact === "::"
    || compact.startsWith("fc")
    || compact.startsWith("fd")
    || compact.startsWith("fe8")
    || compact.startsWith("fe9")
    || compact.startsWith("fea")
    || compact.startsWith("feb")
    || compact.startsWith("ff")
    || compact.startsWith("2001:db8")
    || compact.startsWith("::ffff:10.")
    || compact.startsWith("::ffff:127.")
    || compact.startsWith("::ffff:169.254.")
    || compact.startsWith("::ffff:192.168.");
}

export function normalizePublicUrl(input: string): URL {
  const trimmed = String(input || "").trim();
  if (!trimmed || trimmed.length > 2_048) throw new Error("Введите корректный URL длиной до 2048 символов.");
  const withScheme = /^[a-z][a-z\d+.-]*:\/\//iu.test(trimmed) ? trimmed : `https://${trimmed}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error("Не удалось распознать адрес сайта.");
  }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Поддерживаются только HTTP и HTTPS.");
  if (url.username || url.password) throw new Error("URL с логином или паролем не поддерживается.");
  if (url.port && !["80", "443"].includes(url.port)) throw new Error("Проверка нестандартных портов отключена из соображений безопасности.");
  url.hash = "";

  const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
  if (
    hostname === "localhost"
    || hostname.length > 253
    || BLOCKED_HOST_SUFFIXES.some((suffix) => hostname.endsWith(suffix))
    || isPrivateIp(hostname)
  ) {
    throw new Error("Локальные, служебные и частные адреса проверять нельзя.");
  }
  return url;
}

interface DnsAnswer {
  type?: number;
  data?: string;
}

async function dnsQuery(hostname: string, type: "A" | "AAAA", fetcher: typeof fetch): Promise<string[]> {
  const endpoint = new URL("https://cloudflare-dns.com/dns-query");
  endpoint.searchParams.set("name", hostname);
  endpoint.searchParams.set("type", type);
  const response = await fetcher(endpoint, {
    headers: { accept: "application/dns-json" },
    redirect: "manual",
  });
  if (!response.ok) throw new Error("DNS-проверка сайта временно недоступна.");
  const payload = await response.json() as { Status?: number; Answer?: DnsAnswer[] };
  if (payload.Status !== 0 && payload.Status !== 3) throw new Error("Не удалось проверить DNS сайта.");
  return (payload.Answer || [])
    .filter((answer) => answer.type === 1 || answer.type === 28)
    .map((answer) => String(answer.data || "").trim())
    .filter(Boolean);
}

export async function assertPublicDns(url: URL, fetcher: typeof fetch = fetch): Promise<void> {
  if (isPrivateIp(url.hostname)) throw new Error("Частные IP-адреса проверять нельзя.");
  if (ipv4Parts(url.hostname) || url.hostname.includes(":")) return;
  const [ipv4, ipv6] = await Promise.all([
    dnsQuery(url.hostname, "A", fetcher),
    dnsQuery(url.hostname, "AAAA", fetcher),
  ]);
  const addresses = [...ipv4, ...ipv6];
  if (!addresses.length) throw new Error("Домен не имеет публичного IP-адреса.");
  if (addresses.some(isPrivateIp)) throw new Error("Домен указывает на частный или служебный IP-адрес.");
}

export function parseGitHubRepository(input: string): { owner: string; repo: string; canonical: string } | null {
  const value = String(input || "").trim();
  if (!value) return null;
  let url: URL;
  try {
    url = new URL(/^https?:\/\//iu.test(value) ? value : `https://${value}`);
  } catch {
    throw new Error("Не удалось распознать URL GitHub-репозитория.");
  }
  if (url.hostname.toLowerCase() !== "github.com") throw new Error("Для анализа исходного кода поддерживаются публичные репозитории GitHub.");
  const segments = url.pathname.replace(/^\/+|\/+$/gu, "").split("/");
  if (segments.length !== 2) throw new Error("Укажите ссылку вида github.com/owner/repository.");
  const owner = segments[0];
  const repo = segments[1].replace(/\.git$/u, "");
  const safePart = /^[A-Za-z0-9_.-]{1,100}$/u;
  if (!safePart.test(owner) || !safePart.test(repo)) throw new Error("Некорректное имя GitHub-репозитория.");
  return { owner, repo, canonical: `https://github.com/${owner}/${repo}` };
}
