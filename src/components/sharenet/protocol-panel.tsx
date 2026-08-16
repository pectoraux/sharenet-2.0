"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";

const ALL_CAPS = [
  "MESH_RELAY", "INTERNET_GATEWAY", "CONTENT_SEED", "STORAGE", "DISCOVERY",
  "SYNC", "COMPUTE", "CRYPTO_RELAY", "CRYPTO_GATEWAY", "PAYMENT_RELAY",
];

interface NodeRow {
  nodeId: string;
  publicKeyHex: string;
  capabilities: string[];
  sequence: number;
  acceptedAt: string;
  expiresAt: string;
  expired: boolean;
}

export function ProtocolPanel({ session }: { session: { isDemo: boolean } | null }) {
  const [tab, setTab] = useState<"verify" | "nodes" | "gateway">("verify");

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 text-xs text-amber-300">
        <strong>Private-key boundary (corrective milestone 2026-08-16):</strong> the
        &quot;Generate NodeId&quot; and &quot;Sign Advertisement&quot; endpoints have been
        REMOVED. A node private key MUST be generated, stored, and used locally by the node
        implementation — it MUST NOT traverse the web server, API request body, browser UI,
        logs, database, fixtures, or test snapshots. To produce a signed advertisement, run
        the node-link mini-service locally (<code>bash mini-services/node-link/start-mesh.sh</code>)
        which generates and uses its own keypair.
      </div>
      <div className="flex gap-2 flex-wrap">
        <Button variant={tab === "verify" ? "default" : "outline"} size="sm" onClick={() => setTab("verify")}>Verify + Accept</Button>
        <Button variant={tab === "nodes" ? "default" : "outline"} size="sm" onClick={() => setTab("nodes")}>Accepted Nodes</Button>
        <Button variant={tab === "gateway" ? "default" : "outline"} size="sm" onClick={() => setTab("gateway")}>Gateway Policy</Button>
      </div>
      {tab === "verify" && <VerifyTab session={session} />}
      {tab === "nodes" && <NodesTab />}
      {tab === "gateway" && <GatewayTab session={session} />}
    </div>
  );
}

function VerifyTab({ session }: { session: { isDemo: boolean } | null }) {
  const [hex, setHex] = useState("");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  async function verify() {
    if (!hex) { toast.error("Paste advertisement hex first"); return; }
    setLoading(true);
    const r = await api("/api/sharenet/protocol/verify-advertisement", { method: "POST", body: JSON.stringify({ advertisementHex: hex }) });
    setLoading(false);
    setResult(r.data as Record<string, unknown>);
    if (r.ok && r.data && (r.data as { ok: boolean }).ok) toast.success("Advertisement verified ✓");
    else toast.error((r.data as { reason?: string })?.reason ?? r.error ?? "Verification failed");
  }

  async function accept() {
    if (!session) { toast.error("Sign in to accept advertisements"); return; }
    setLoading(true);
    const r = await api("/api/sharenet/protocol/accept-advertisement", { method: "POST", body: JSON.stringify({ advertisementHex: hex }) });
    setLoading(false);
    if (r.ok) {
      const d = r.data as { ok: boolean; nodeId?: string; stage?: string; reason?: string };
      if (d.ok) { toast.success(`Node accepted: ${d.nodeId?.slice(0, 24)}…`); }
      else toast.error(`${d.stage ?? "rejected"}: ${d.reason ?? "unknown"}`);
    } else toast.error(r.error ?? "Accept failed");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Verify + Accept NodeAdvertisement</CardTitle>
        <CardDescription>
          Verify runs spec/03 §5 checks (signature, identity binding, timestamps, expiry, canonical encoding).
          Accept runs the FULL pipeline: verify → check sequence floor → accept → persist NodeRecord.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-2">
          <Label>Advertisement hex (canonical CBOR)</Label>
          <Textarea value={hex} onChange={(e) => setHex(e.target.value)} placeholder="Paste hex here…" className="font-mono text-xs min-h-[100px]" />
        </div>
        <div className="flex gap-2 flex-wrap">
          <Button onClick={verify} disabled={loading || !hex} variant="outline">{loading ? "Working…" : "Verify only"}</Button>
          <Button onClick={accept} disabled={loading || !hex || !session}>{loading ? "Working…" : "Verify + Accept (persist)"}</Button>
        </div>
        {!session && <p className="text-xs text-muted-foreground">Sign in (any role) to run the full acceptance pipeline.</p>}
        {result && (
          <pre className="text-xs p-3 bg-muted/30 rounded overflow-x-auto max-h-[400px] sharenet-scroll">{JSON.stringify(result, null, 2)}</pre>
        )}
      </CardContent>
    </Card>
  );
}

function NodesTab() {
  const [nodes, setNodes] = useState<NodeRow[]>([]);
  const [loading, setLoading] = useState(false);
  const reload = useCallback(async () => {
    setLoading(true);
    const r = await api<{ nodes: NodeRow[] }>("/api/sharenet/protocol/nodes");
    if (r.ok && r.data) setNodes(r.data.nodes);
    setLoading(false);
  }, []);
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      await reload();
    })();
    return () => { cancelled = true; };
  }, [reload]);
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">Accepted NodeRecords <Button size="sm" variant="ghost" onClick={reload} disabled={loading}>{loading ? "…" : "↻"}</Button></CardTitle>
        <CardDescription>Live registry of AuthenticatedNodeRecords. Per ADR-0007 these all entered through the verify → accept pipeline.</CardDescription>
      </CardHeader>
      <CardContent className="space-y-2 max-h-[500px] overflow-y-auto sharenet-scroll">
        {nodes.length === 0 && <div className="text-sm text-muted-foreground">No nodes accepted yet. Sign + accept one in the previous tabs.</div>}
        {nodes.map((n) => (
          <div key={n.nodeId} className="border border-border rounded-md p-3 space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs text-emerald-300">{n.nodeId.slice(0, 32)}…</span>
              {n.expired && <Badge variant="destructive">EXPIRED</Badge>}
              {!n.expired && <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">LIVE</Badge>}
              <span className="text-xs text-muted-foreground ml-auto">seq={n.sequence}</span>
            </div>
            <div className="text-xs text-muted-foreground">pub: {n.publicKeyHex.slice(0, 32)}…</div>
            <div className="flex gap-1 flex-wrap">
              {n.capabilities.map((c) => <Badge key={c} variant="secondary" className="text-xs">{c}</Badge>)}
            </div>
            <div className="text-xs text-muted-foreground">accepted {new Date(n.acceptedAt).toLocaleString()} · expires {new Date(n.expiresAt).toLocaleString()}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function GatewayTab({ session }: { session: { isDemo: boolean } | null }) {
  const [gatewayNodeId, setGatewayNodeId] = useState("");
  const [peerNodeId, setPeerNodeId] = useState("");
  const [destination, setDestination] = useState("example.com:443");
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  async function evaluate() {
    if (!session) { toast.error("Sign in to evaluate gateway policy"); return; }
    setLoading(true);
    const r = await api("/api/sharenet/protocol/gateway-policy", {
      method: "POST",
      body: JSON.stringify({ gatewayNodeId, peerNodeId, destination }),
    });
    setLoading(false);
    setResult(r.data as Record<string, unknown>);
    if (r.ok) {
      const decision = (r.data as { result?: { decision?: string } })?.result?.decision;
      toast[decision === "ALLOW" ? "success" : "error"](`${decision} — ${(r.data as { result?: { reason?: string } })?.result?.reason ?? ""}`);
    } else toast.error(r.error ?? "Evaluation failed");
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Gateway Policy Stub (ADR-0011)</CardTitle>
        <CardDescription>
          Enforces all 11 spec/09 §3 guards (destination policy, private-address blocking, loopback, link-local, SSRF, per-peer quota, global quota, rate limit, revocation, bandwidth shaping, abuse controls).
          <strong> Does NOT forward to real Internet</strong> — that is Phase 8. Returns a structured policy decision.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid gap-2">
          <Label>Gateway NodeId</Label>
          <Input value={gatewayNodeId} onChange={(e) => setGatewayNodeId(e.target.value)} placeholder="node:..." className="font-mono text-xs" />
          <p className="text-xs text-muted-foreground">Tip: generate one in the &quot;Generate NodeId&quot; tab.</p>
        </div>
        <div className="grid gap-2">
          <Label>Peer NodeId (the requester)</Label>
          <Input value={peerNodeId} onChange={(e) => setPeerNodeId(e.target.value)} placeholder="node:..." className="font-mono text-xs" />
        </div>
        <div className="grid gap-2">
          <Label>Destination (host or host:port)</Label>
          <Input value={destination} onChange={(e) => setDestination(e.target.value)} placeholder="example.com:443" />
          <p className="text-xs text-muted-foreground">Try <code>127.0.0.1</code>, <code>10.0.0.1</code>, <code>169.254.169.254</code> to see guards fire.</p>
        </div>
        <Button onClick={evaluate} disabled={loading || !session || !gatewayNodeId || !peerNodeId}>{loading ? "Evaluating…" : "Evaluate policy"}</Button>
        {!session && <p className="text-xs text-muted-foreground">Sign in to evaluate.</p>}
        {result && (
          <pre className="text-xs p-3 bg-muted/30 rounded overflow-x-auto max-h-[400px] sharenet-scroll">{JSON.stringify(result, null, 2)}</pre>
        )}
      </CardContent>
    </Card>
  );
}

function KV({ label, value, mono, accent, secret }: { label: string; value: string; mono?: boolean; accent?: boolean; secret?: boolean }) {
  const [revealed, setRevealed] = useState(!secret);
  return (
    <div className="grid gap-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      <div className="flex items-center gap-2">
        <code className={`flex-1 text-xs ${mono ? "font-mono" : ""} ${accent ? "text-emerald-300" : ""} bg-muted/30 rounded p-2 break-all`}>
          {secret && !revealed ? "•".repeat(value.length) : value}
        </code>
        {secret && (
          <Button size="sm" variant="ghost" onClick={() => setRevealed(!revealed)}>{revealed ? "Hide" : "Reveal"}</Button>
        )}
      </div>
    </div>
  );
}
