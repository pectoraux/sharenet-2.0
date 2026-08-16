/**
 * Tiny fetch helper used by the dashboard client. All API routes are
 * relative paths under /api/sharenet/* — never absolute.
 */

export async function api<T = unknown>(
  path: string,
  opts: RequestInit = {},
): Promise<{ ok: boolean; data?: T; error?: string; status: number }> {
  try {
    const res = await fetch(path, {
      ...opts,
      headers: {
        "Content-Type": "application/json",
        ...(opts.headers ?? {}),
      },
      credentials: "include",
    });
    const text = await res.text();
    let data: unknown = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!res.ok) {
      const errObj = data as { error?: string; message?: string };
      return { ok: false, error: errObj?.error ?? errObj?.message ?? `HTTP ${res.status}`, status: res.status };
    }
    return { ok: true, data: data as T, status: res.status };
  } catch (e) {
    return { ok: false, error: (e as Error).message, status: 0 };
  }
}
