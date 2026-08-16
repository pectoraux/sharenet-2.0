"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";

interface WaitlistEntry {
  id: string;
  email: string;
  name: string | null;
  requestedUserType: string;
  status: string;
  notes: string | null;
  createdAt: string;
  reviewedAt: string | null;
  reviewedBy: { email: string; name: string | null } | null;
}

interface UserRow {
  id: string;
  email: string;
  name: string | null;
  role: string;
  disabled: boolean;
  isDemo: boolean;
  createdAt: string;
}

interface AuditEntry {
  id: string;
  action: string;
  actor: { email: string; name: string | null; isDemo: boolean } | null;
  targetEmail: string | null;
  targetNodeId: string | null;
  detail: string | null;
  createdAt: string;
}

export function AdminPanel({ session }: { session: { role: string; isDemo: boolean } | null }) {
  const [entries, setEntries] = useState<WaitlistEntry[]>([]);
  const [users, setUsers] = useState<UserRow[]>([]);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [tab, setTab] = useState<"waitlist" | "users" | "audit">("waitlist");

  const reload = useCallback(async () => {
    setLoading(true);
    if (tab === "waitlist") {
      const r = await api<{ entries: WaitlistEntry[] }>("/api/sharenet/waitlist/list?limit=100");
      if (r.ok && r.data) setEntries(r.data.entries);
    } else if (tab === "users") {
      const r = await api<{ users: UserRow[] }>("/api/sharenet/admin/users?includeDemo=1");
      if (r.ok && r.data) setUsers(r.data.users);
    } else if (tab === "audit") {
      const r = await api<{ entries: AuditEntry[] }>("/api/sharenet/audit?limit=100");
      if (r.ok && r.data) setAudit(r.data.entries);
    }
    setLoading(false);
  }, [tab]);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      await reload();
    })();
    return () => { cancelled = true; };
  }, [reload]);

  if (!session) {
    return <Card><CardContent className="p-6 text-muted-foreground">Sign in as a real admin to access the admin panel.</CardContent></Card>;
  }
  if (session.role !== "ADMIN") {
    return <Card><CardContent className="p-6 text-muted-foreground">Admin role required.</CardContent></Card>;
  }
  if (session.isDemo) {
    return (
      <Card className="border-amber-500/30">
        <CardHeader><CardTitle className="text-amber-400">Demo Admin — Read-Only</CardTitle></CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>You are logged in as the <strong>demo admin</strong>. Per ADR-0009, the demo admin is NOT the real admin bootstrap account and cannot perform real administrative actions.</p>
          <p>To exercise real admin actions, set <code className="text-emerald-400">ADMIN_BOOTSTRAP_USERNAME</code> + <code className="text-emerald-400">ADMIN_BOOTSTRAP_PASSWORD</code> environment variables and log in via the real login form.</p>
        </CardContent>
      </Card>
    );
  }

  async function review(waitlistId: string, decision: "APPROVE" | "REJECT" | "INVITE") {
    const r = await api("/api/sharenet/waitlist/review", { method: "POST", body: JSON.stringify({ waitlistId, decision }) });
    if (r.ok) { toast.success(`${decision} recorded`); reload(); }
    else toast.error(r.error ?? "Review failed");
  }
  async function createAccount(waitlistId: string) {
    const r = await api("/api/sharenet/waitlist/create-account", { method: "POST", body: JSON.stringify({ waitlistId }) });
    if (r.ok && r.data) {
      const d = r.data as { email: string; initialPassword: string; role: string };
      toast.success(`Account created for ${d.email}`);
      // Show the initial password once (admin must communicate out-of-band).
      alert(`Account created.\nEmail: ${d.email}\nRole: ${d.role}\nInitial password (communicate out-of-band):\n${d.initialPassword}`);
      reload();
    } else toast.error(r.error ?? "Account creation failed");
  }
  async function disable(userId: string) {
    const r = await api("/api/sharenet/admin/disable", { method: "POST", body: JSON.stringify({ userId }) });
    if (r.ok) { toast.success("Account disabled"); reload(); } else toast.error(r.error ?? "Disable failed");
  }
  async function enable(userId: string) {
    const r = await api("/api/sharenet/admin/enable", { method: "POST", body: JSON.stringify({ userId }) });
    if (r.ok) { toast.success("Account enabled"); reload(); } else toast.error(r.error ?? "Enable failed");
  }
  async function changeRole(userId: string, role: string) {
    const r = await api("/api/sharenet/admin/role", { method: "POST", body: JSON.stringify({ userId, role }) });
    if (r.ok) { toast.success(`Role changed to ${role}`); reload(); } else toast.error(r.error ?? "Role change failed");
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2 flex-wrap">
        <Button variant={tab === "waitlist" ? "default" : "outline"} size="sm" onClick={() => setTab("waitlist")}>Waitlist</Button>
        <Button variant={tab === "users" ? "default" : "outline"} size="sm" onClick={() => setTab("users")}>Users</Button>
        <Button variant={tab === "audit" ? "default" : "outline"} size="sm" onClick={() => setTab("audit")}>Audit Log</Button>
        <Button variant="ghost" size="sm" onClick={reload} disabled={loading}>{loading ? "Reloading…" : "Reload"}</Button>
      </div>

      {tab === "waitlist" && (
        <Card>
          <CardHeader>
            <CardTitle>Waitlist Review</CardTitle>
            <CardDescription>Approve → create account. Per spec/00 §7 the pipeline is: PENDING → APPROVED → ACCOUNT_CREATED.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3 max-h-[600px] overflow-y-auto sharenet-scroll">
            {entries.length === 0 && <div className="text-sm text-muted-foreground">No entries.</div>}
            {entries.map((e) => (
              <div key={e.id} className="border border-border rounded-md p-3 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <StatusBadge status={e.status} />
                  <span className="font-mono text-xs text-muted-foreground">{e.email}</span>
                  {e.name && <span className="text-sm">— {e.name}</span>}
                  <Badge variant="outline" className="ml-auto">{e.requestedUserType}</Badge>
                </div>
                {e.notes && <div className="text-xs text-muted-foreground italic">{e.notes}</div>}
                <div className="text-xs text-muted-foreground">
                  Submitted {new Date(e.createdAt).toLocaleString()}
                  {e.reviewedBy && <> · reviewed by {e.reviewedBy.email}</>}
                </div>
                <div className="flex gap-2 flex-wrap">
                  {e.status === "PENDING" && (
                    <>
                      <Button size="sm" variant="default" onClick={() => review(e.id, "APPROVE")}>Approve</Button>
                      <Button size="sm" variant="outline" onClick={() => review(e.id, "INVITE")}>Invite</Button>
                      <Button size="sm" variant="destructive" onClick={() => review(e.id, "REJECT")}>Reject</Button>
                    </>
                  )}
                  {(e.status === "APPROVED" || e.status === "INVITED") && (
                    <Button size="sm" onClick={() => createAccount(e.id)}>Create account</Button>
                  )}
                  {e.status === "ACCOUNT_CREATED" && <Badge variant="outline" className="text-emerald-300">Account created ✓</Badge>}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {tab === "users" && (
        <Card>
          <CardHeader>
            <CardTitle>Real + Demo User Accounts</CardTitle>
            <CardDescription>Disable / enable / change role. Demo accounts are marked.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 max-h-[600px] overflow-y-auto sharenet-scroll">
            {users.length === 0 && <div className="text-sm text-muted-foreground">No users.</div>}
            {users.map((u) => (
              <div key={u.id} className="border border-border rounded-md p-3 flex items-center gap-3 flex-wrap">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs truncate">{u.email}</span>
                    {u.isDemo && <Badge variant="outline" className="text-amber-400 border-amber-500/40">DEMO</Badge>}
                    {u.disabled && <Badge variant="destructive">DISABLED</Badge>}
                  </div>
                  <div className="text-xs text-muted-foreground">{u.name ?? "no name"} · created {new Date(u.createdAt).toLocaleDateString()}</div>
                </div>
                <Select value={u.role} onValueChange={(v) => changeRole(u.id, v)} disabled={u.isDemo}>
                  <SelectTrigger className="w-40 h-8"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {["USER", "RELAY_OPERATOR", "GATEWAY_OPERATOR", "CONTENT_PROVIDER", "STORAGE_PROVIDER", "COMPUTE_PROVIDER", "ADMIN"].map((r) => (
                      <SelectItem key={r} value={r}>{r}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {!u.isDemo && (
                  u.disabled
                    ? <Button size="sm" variant="outline" onClick={() => enable(u.id)}>Enable</Button>
                    : <Button size="sm" variant="destructive" onClick={() => disable(u.id)}>Disable</Button>
                )}
              </div>
            ))}
          </CardContent>
        </Card>
      )}

      {tab === "audit" && (
        <Card>
          <CardHeader>
            <CardTitle>Audit Log</CardTitle>
            <CardDescription>Append-only. Every auth event, role change, waitlist decision, node acceptance, gateway policy decision.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1 max-h-[600px] overflow-y-auto sharenet-scroll font-mono text-xs">
            {audit.length === 0 && <div className="text-muted-foreground">No audit entries.</div>}
            {audit.map((a) => (
              <div key={a.id} className="border-l-2 border-emerald-500/40 pl-2 py-1">
                <div className="flex items-center gap-2">
                  <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">{a.action}</Badge>
                  <span className="text-muted-foreground">{new Date(a.createdAt).toLocaleString()}</span>
                  {a.actor && <span className="text-muted-foreground">by {a.actor.email}{a.actor.isDemo ? " (demo)" : ""}</span>}
                </div>
                {a.targetEmail && <div className="text-muted-foreground">target email: {a.targetEmail}</div>}
                {a.targetNodeId && <div className="text-muted-foreground">target node: {a.targetNodeId.slice(0, 24)}…</div>}
                {a.detail && <div className="text-muted-foreground truncate">{a.detail}</div>}
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    PENDING: "border-amber-500/40 text-amber-300",
    APPROVED: "border-emerald-500/40 text-emerald-300",
    REJECTED: "border-destructive/40 text-destructive",
    INVITED: "border-emerald-500/40 text-emerald-300",
    ACCOUNT_CREATED: "border-emerald-500/60 text-emerald-300 bg-emerald-500/10",
  };
  return <Badge variant="outline" className={colors[status] ?? ""}>{status}</Badge>;
}
