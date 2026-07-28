declare module "cloudflare:workers" {
  export const env: Record<string, unknown> & { DB?: D1Database };
}

interface Fetcher {
  fetch(request: Request): Promise<Response>;
}

interface D1Database {
  prepare(query: string): unknown;
}
