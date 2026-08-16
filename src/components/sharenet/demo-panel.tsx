"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";

interface DemoPersona {
  slug: string;
  label: string;
  description: string;
  role: string;
  sortOrder: number;
}

export function DemoPanel({ onLoggedIn }: { onLoggedIn: () => void }) {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [personas, setPersonas] = useState<DemoPersona[]>([]);
  const [busySlug, setBusySlug] = useState<string | null>(null);

  const reload = useCallback(async () => {
    const r = await api<{ enabled: boolean; personas: DemoPersona[] }>("/api/sharenet/demo/status");
    if (r.ok && r.data) { setEnabled(r.data.enabled); setPersonas(r.data.personas); }
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      await reload();
    })();
    return () => { cancelled = true; };
  }, [reload]);

  async function quickLogin(slug: string) {
    setBusySlug(slug);
    const r = await api("/api/sharenet/demo/quick-login", { method: "POST", body: JSON.stringify({ slug }) });
    setBusySlug(null);
    if (r.ok) {
      toast.success(`Logged in as ${slug}`);
      onLoggedIn();
    } else {
      toast.error(r.error ?? "Quick-login failed");
    }
  }

  return (
    <Card className="border-amber-500/30">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <span className="text-amber-400">◐</span> Demo Quick-Login
        </CardTitle>
        <CardDescription>
          Per spec/00 §10 + §28: isolated demo identities for every supported user type.
          Demo admin is NOT the real admin bootstrap account (ADR-0009).
          Demo login is gated by the <code className="text-emerald-400">ENABLE_DEMO_LOGIN</code> env flag.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {enabled === null && <div className="text-sm text-muted-foreground">Checking demo status…</div>}
        {enabled === false && (
          <div className="text-sm text-destructive border border-destructive/30 bg-destructive/10 rounded-md p-3">
            Demo login is currently <strong>disabled</strong> (ENABLE_DEMO_LOGIN is not truthy).
            Set <code className="text-emerald-400">ENABLE_DEMO_LOGIN=1</code> to enable.
          </div>
        )}
        {enabled && (
          <div className="grid gap-2 sm:grid-cols-2">
            {personas.map((p) => (
              <div key={p.slug} className="border border-border rounded-md p-3 flex flex-col gap-2 bg-muted/20">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{p.label}</span>
                  <Badge variant="outline" className="ml-auto text-emerald-300 border-emerald-500/40">{p.role}</Badge>
                </div>
                <p className="text-xs text-muted-foreground flex-1">{p.description}</p>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => quickLogin(p.slug)}
                  disabled={busySlug === p.slug}
                  className="border-amber-500/40 text-amber-300 hover:bg-amber-500/10"
                >
                  {busySlug === p.slug ? "Logging in…" : `Quick-login as ${p.label}`}
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
