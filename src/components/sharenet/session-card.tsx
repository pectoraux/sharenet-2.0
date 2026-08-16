"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";
import type { SessionInfo } from "./use-session";

export function SessionCard({ session, onRefresh }: { session: SessionInfo | null; onRefresh: () => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  async function login() {
    if (!email || !password) { toast.error("Email + password required"); return; }
    setLoading(true);
    const r = await api("/api/sharenet/auth/login", { method: "POST", body: JSON.stringify({ email, password }) });
    setLoading(false);
    if (r.ok) { toast.success("Logged in"); setEmail(""); setPassword(""); onRefresh(); }
    else toast.error(r.error ?? "Login failed");
  }
  async function logout() {
    const r = await api("/api/sharenet/auth/logout", { method: "POST" });
    if (r.ok) { toast.success("Logged out"); onRefresh(); }
  }

  if (session) {
    return (
      <Card className="border-emerald-500/30">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <span className="text-emerald-400">●</span> Session active
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="font-mono text-xs text-emerald-300">{session.email}</div>
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">{session.role}</Badge>
            {session.isDemo && <Badge variant="outline" className="text-amber-400 border-amber-500/40">DEMO</Badge>}
            <span className="text-xs text-muted-foreground">{session.name ?? "no name"}</span>
          </div>
          {session.isDemo && (
            <div className="text-xs text-amber-400 border border-amber-500/30 bg-amber-500/10 rounded p-2">
              Demo session. Real mutations are blocked (ADR-0009).
            </div>
          )}
          <Button size="sm" variant="outline" onClick={logout}>Sign out</Button>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm">Sign in (real account)</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        <div className="grid gap-1">
          <Label htmlFor="login-email" className="text-xs">Email</Label>
          <Input id="login-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} className="h-8 text-sm" />
        </div>
        <div className="grid gap-1">
          <Label htmlFor="login-password" className="text-xs">Password</Label>
          <Input id="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} className="h-8 text-sm" />
        </div>
        <Button size="sm" onClick={login} disabled={loading} className="w-full">{loading ? "…" : "Sign in"}</Button>
        <p className="text-xs text-muted-foreground">
          The real admin is provisioned via <code className="text-emerald-400">ADMIN_BOOTSTRAP_USERNAME</code> + <code className="text-emerald-400">ADMIN_BOOTSTRAP_PASSWORD</code> env vars (spec/00 §8).
        </p>
      </CardContent>
    </Card>
  );
}
