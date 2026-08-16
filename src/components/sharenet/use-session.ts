"use client";

import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/sharenet/fetch";

export interface SessionInfo {
  userId: string;
  email: string;
  name: string | null;
  role: string;
  isDemo: boolean;
  expiresAt?: string;
}

interface MeResponse {
  ok: boolean;
  session: SessionInfo | null;
}

/** Hook that loads the current session (or null) and provides a refresh. */
export function useSession() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    const r = await api<MeResponse>("/api/sharenet/auth/me");
    if (r.ok && r.data?.session) {
      setSession(r.data.session);
    } else {
      setSession(null);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      await refresh();
    })();
    return () => { cancelled = true; };
  }, [refresh]);

  return { session, loading, refresh };
}
