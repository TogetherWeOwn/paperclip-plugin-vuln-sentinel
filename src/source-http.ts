export type SourceFetch = (url: string, init: RequestInit) => Promise<Response>;

export class SourceAttention extends Error {
  constructor(readonly code: string) {
    super(`Source requires attention: ${code}`);
    this.name = "SourceAttention";
  }
}

/** Fixed-provider callers choose the URL. No redirects, retries or unbounded bodies. */
export async function sourceRequest(
  fetch: SourceFetch, url: string, init: RequestInit, maxBytes = 4 * 1024 * 1024, timeoutMs = 30_000,
): Promise<{ status: number; etag: string | null; body: unknown }> {
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const request = async () => {
    const response = await fetch(url, { ...init, redirect: "error", signal: controller.signal });
    const etag = response.headers.get("etag");
    if (response.status !== 200) {
      await response.body?.cancel();
      return { status: response.status, etag, body: null };
    }
    if (!response.body) throw new SourceAttention("empty_response");
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) throw new SourceAttention("response_too_large");
        chunks.push(value);
      }
    } finally {
      await reader.cancel().catch(() => undefined);
    }
    try {
      return { status: response.status, etag, body: JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown };
    } catch {
      throw new SourceAttention("invalid_json");
    }
  };
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new SourceAttention("request_timeout"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([request(), deadline]);
  } catch (error) {
    if (error instanceof SourceAttention) throw error;
    // Transport errors may contain URLs, tokens or provider response bodies.
    throw new SourceAttention("transport_failed");
  } finally {
    clearTimeout(timer);
  }
}

export function sourceBudget(fetch: SourceFetch) {
  const deadline = Date.now() + 240_000;
  let requests = 0;
  return (url: string, init: RequestInit) => {
    if (++requests > 128 || Date.now() >= deadline) throw new SourceAttention("query_budget_exhausted");
    return sourceRequest(fetch, url, init, 4 * 1024 * 1024, Math.min(30_000, deadline - Date.now()));
  };
}

export function object(value: unknown, code: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new SourceAttention(code);
  return value as Record<string, unknown>;
}

export function text(value: unknown, code: string, max = 2048): string {
  if (typeof value !== "string" || !value.trim() || value !== value.trim()
    || value.length > max || /[\x00-\x1f\x7f]/u.test(value)) {
    throw new SourceAttention(code);
  }
  return value;
}

export function timestamp(value: unknown, code: string): string {
  const result = text(value, code, 64);
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(result)
    || !Number.isFinite(Date.parse(result))) throw new SourceAttention(code);
  const normalized = new Date(result).toISOString();
  if (normalized.slice(0, 19) !== result.slice(0, 19)) throw new SourceAttention(code);
  // Preserve sub-millisecond advisory revisions; truncating them can hide modifications.
  return result;
}
