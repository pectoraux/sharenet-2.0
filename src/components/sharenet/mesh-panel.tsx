"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";

interface MeshNode {
  nodeId: string;
  name: string;
  publicKeyHex: string;
  wireEndpoint: string;
  reachable: boolean;
}
interface MeshLink {
  linkId: string;
  localNodeId: string;
  remoteNodeId: string;
  remoteEndpoint: string;
  remoteCapabilities: string[];
  state: string;
  observedFromNode: string;
  createdAt: number;
  stateChangedAt: number;
}
interface NodeProcess {
  name: string;
  controlPort: number;
  wirePort: number;
  reachable: boolean;
  nodeId: string | null;
  eventCount: number;
  recentEvents: Array<{ type: string; linkId: string; remoteNodeId?: string; remoteEndpoint?: string; at: number }>;
}
interface MeshState {
  ok: boolean;
  nodes: MeshNode[];
  links: MeshLink[];
  nodeProcesses: NodeProcess[];
  directionalInvariantHolds: boolean;
}

export function MeshPanel() {
  const [mesh, setMesh] = useState<MeshState | null>(null);
  const [loading, setLoading] = useState(false);
  const [dialHost, setDialHost] = useState("127.0.0.1");
  const [dialPort, setDialPort] = useState("7789");
  const [dialing, setDialing] = useState(false);

  const reload = useCallback(async () => {
    setLoading(true);
    const r = await api<MeshState>("/api/sharenet/mesh/mesh-state");
    if (r.ok && r.data) setMesh(r.data);
    setLoading(false);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setInterval>;
    (async () => {
      if (cancelled) return;
      await reload();
      // Auto-refresh every 3s while the panel is open so the live mesh
      // updates as links come and go.
      timer = setInterval(reload, 3000);
    })();
    return () => { cancelled = true; clearInterval(timer); };
  }, [reload]);

  async function dial(sourceControlPort: number, sourceName: string) {
    setDialing(true);
    const r = await api(`/api/sharenet/mesh/dial?XTransformPort=${sourceControlPort}`, {
      method: "POST",
      body: JSON.stringify({ host: dialHost, port: parseInt(dialPort, 10) }),
    });
    setDialing(false);
    if (r.ok && r.data && (r.data as { ok: boolean }).ok) {
      const d = r.data as { linkId: string };
      toast.success(`${sourceName} → ${dialHost}:${dialPort} LinkUp`);
      await reload();
    } else {
      toast.error(`${sourceName} dial failed: ${(r.data as { reason?: string })?.reason ?? r.error}`);
    }
  }

  const reachable = mesh?.nodes.filter((n) => n.reachable).length ?? 0;
  const total = mesh?.nodes.length ?? 0;
  const upLinks = mesh?.links.filter((l) => l.state === "LINK_UP").length ?? 0;

  return (
    <div className="space-y-4">
      <Card className="border-emerald-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-3">
            Live Mesh — Phase 3
            {mesh && (
              <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">
                {reachable}/{total} nodes reachable
              </Badge>
            )}
            {mesh && (
              <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">
                {upLinks} link{upLinks === 1 ? "" : "s"} LINK_UP
              </Badge>
            )}
          </CardTitle>
          <CardDescription>
            Per spec/00 §37: <strong>real independent processes</strong> establishing authenticated
            directed links over a real TCP socket. No simulator, no shared in-memory graph, no fake transport.
            Each node is a separate Bun process with its own Ed25519 keypair + NodeId.
            <br />
            <span className="text-xs text-muted-foreground">
              Auto-refreshes every 3s. Node A: control=3001 wire=7788 · Node B: control=3002 wire=7789.
            </span>
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2 flex-wrap">
            <Button size="sm" onClick={reload} disabled={loading}>{loading ? "Refreshing…" : "↻ Refresh"}</Button>
            {mesh?.directionalInvariantHolds === true && (
              <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">
                ✓ directional LinkId invariant holds
              </Badge>
            )}
            {mesh?.directionalInvariantHolds === false && (
              <Badge variant="destructive">✗ LinkId collision detected</Badge>
            )}
          </div>

          {/* Dial-out control */}
          <div className="border border-border rounded-md p-3 space-y-2 bg-muted/10">
            <div className="text-sm font-medium">Dial out (initiate a new directed link)</div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 items-end">
              <div><Label className="text-xs">Source node</Label></div>
              <div><Label className="text-xs">Target host</Label><Input value={dialHost} onChange={(e) => setDialHost(e.target.value)} className="h-8 text-sm" /></div>
              <div><Label className="text-xs">Target wire port</Label><Input value={dialPort} onChange={(e) => setDialPort(e.target.value)} className="h-8 text-sm" /></div>
              <div className="text-xs text-muted-foreground">Target = Node B by default</div>
            </div>
            <div className="flex gap-2 flex-wrap">
              {mesh?.nodeProcesses.map((np) => (
                <Button
                  key={np.name}
                  size="sm"
                  variant="outline"
                  disabled={dialing || !np.reachable}
                  onClick={() => dial(np.controlPort, np.name)}
                  className="border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/10"
                >
                  {dialing ? "Dialing…" : `${np.name} dials →`}
                </Button>
              ))}
            </div>
          </div>

          {/* Node processes */}
          <div className="grid md:grid-cols-2 gap-3">
            {mesh?.nodeProcesses.map((np) => (
              <div key={np.name} className={`border rounded-md p-3 ${np.reachable ? "border-emerald-500/30 bg-emerald-500/5" : "border-destructive/40 bg-destructive/5"}`}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-medium">{np.name}</span>
                  <Badge variant="outline" className={np.reachable ? "text-emerald-300 border-emerald-500/40" : "text-destructive border-destructive/40"}>
                    {np.reachable ? "● reachable" : "○ unreachable"}
                  </Badge>
                  <span className="text-xs text-muted-foreground ml-auto">control=:{np.controlPort} wire=:{np.wirePort}</span>
                </div>
                {np.nodeId && (
                  <div className="text-xs font-mono text-emerald-300 break-all">{np.nodeId}</div>
                )}
                {np.nodeId && (
                  <div className="text-xs text-muted-foreground mt-1">
                    pubkey: {mesh?.nodes.find((n) => n.nodeId === np.nodeId)?.publicKeyHex.slice(0, 24)}…
                  </div>
                )}
                {np.recentEvents.length > 0 && (
                  <div className="mt-2 space-y-0.5">
                    <div className="text-xs text-muted-foreground">recent events:</div>
                    {np.recentEvents.slice().reverse().map((e, i) => (
                      <div key={i} className="text-xs font-mono text-muted-foreground">
                        <span className={e.type === "LINK_UP" ? "text-emerald-400" : e.type === "LINK_DOWN" ? "text-destructive" : "text-amber-400"}>
                          {e.type}
                        </span>
                        {" "}
                        {e.remoteNodeId ? e.remoteNodeId.slice(0, 16) + "…" : e.remoteEndpoint ?? ""}
                      </div>
                    ))}
                  </div>
                )}
                {!np.reachable && (
                  <div className="text-xs text-muted-foreground mt-2">
                    Run <code className="text-emerald-400">bash mini-services/node-link/start-mesh.sh</code> to start.
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Directed links visualization */}
          <div>
            <div className="text-sm font-medium mb-2">Directed links ({mesh?.links.length ?? 0})</div>
            {mesh && mesh.links.length === 0 && (
              <div className="text-sm text-muted-foreground border border-border rounded-md p-3">
                No links yet. Use the dial control above — e.g., <strong>node-a dials → 127.0.0.1:7789</strong> (Node B's wire port).
              </div>
            )}
            <div className="space-y-2 max-h-[400px] overflow-y-auto sharenet-scroll">
              {mesh?.links.map((l) => (
                <div key={l.linkId} className="border border-emerald-500/30 bg-emerald-500/5 rounded-md p-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge variant="outline" className={l.state === "LINK_UP" ? "text-emerald-300 border-emerald-500/40" : "text-destructive border-destructive/40"}>
                      {l.state}
                    </Badge>
                    <span className="text-xs font-mono">
                      <span className="text-emerald-300">{l.localNodeId.slice(0, 16)}</span>
                      <span className="text-muted-foreground">→</span>
                      <span className="text-emerald-300">{l.remoteNodeId.slice(0, 16)}</span>
                    </span>
                    <span className="text-xs text-muted-foreground ml-auto">via {l.remoteEndpoint}</span>
                  </div>
                  <div className="text-xs text-muted-foreground mt-1">
                    linkId: <span className="font-mono">{l.linkId.slice(0, 32)}…</span>
                  </div>
                  <div className="text-xs text-muted-foreground">
                    peer caps: [{l.remoteCapabilities.join(", ")}]
                  </div>
                  <div className="text-xs text-muted-foreground">
                    observed from: <span className="font-mono">{l.observedFromNode}</span> · created {new Date(l.createdAt).toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Directional invariant explainer */}
          <div className="border border-border rounded-md p-3 text-xs text-muted-foreground">
            <strong className="text-foreground">Directional invariant (spec/04, ADR-0014):</strong> a link
            A→B has a different LinkId than B→A, even with the same nonces, because the local/remote
            roles are swapped in the hash input. Each process maintains its OWN link registry with
            its localNodeId first — so when A dials B, both processes record a link, but the two
            LinkIds differ (A's link is A→B; B's link is B→A from B's perspective). This makes
            the directed invariant <strong>structurally enforced</strong> at the data-structure level.
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
