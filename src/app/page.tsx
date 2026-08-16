"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { useSession } from "@/components/sharenet/use-session";
import { SessionCard } from "@/components/sharenet/session-card";
import { SignupPanel } from "@/components/sharenet/signup-panel";
import { AdminPanel } from "@/components/sharenet/admin-panel";
import { DemoPanel } from "@/components/sharenet/demo-panel";
import { ProtocolPanel } from "@/components/sharenet/protocol-panel";
import { ArchitecturePanel } from "@/components/sharenet/architecture-panel";
import { SpecBrowserPanel } from "@/components/sharenet/spec-browser-panel";
import { MeshPanel } from "@/components/sharenet/mesh-panel";

type Tab = "overview" | "signup" | "admin" | "demo" | "protocol" | "architecture" | "mesh" | "spec";

const TABS: { id: Tab; label: string; icon: string }[] = [
  { id: "overview", label: "Overview", icon: "◆" },
  { id: "signup", label: "Waitlist Signup", icon: "✎" },
  { id: "admin", label: "Admin Dashboard", icon: "⚙" },
  { id: "demo", label: "Demo Accounts", icon: "◐" },
  { id: "protocol", label: "Protocol Playground", icon: "⛓" },
  { id: "mesh", label: "Live Mesh", icon: "⇄" },
  { id: "architecture", label: "Architecture Tests", icon: "✓" },
  { id: "spec", label: "Spec & ADR Browser", icon: "▤" },
];

export default function Page() {
  const [tab, setTab] = useState<Tab>("overview");
  const { session, loading, refresh } = useSession();

  return (
    <div className="min-h-screen flex flex-col bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3 flex-wrap">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-md bg-gradient-to-br from-emerald-500 to-emerald-700 flex items-center justify-center text-primary-foreground font-bold text-sm">S</div>
            <div>
              <div className="font-semibold leading-tight">ShareNet <span className="text-emerald-400">2.0</span></div>
              <div className="text-xs text-muted-foreground leading-tight">First Deliverable · Protocol Foundation + Control Plane</div>
            </div>
          </div>
          <nav className="hidden md:flex items-center gap-1 ml-6">
            {TABS.map((t) => (
              <Button
                key={t.id}
                variant={tab === t.id ? "default" : "ghost"}
                size="sm"
                onClick={() => setTab(t.id)}
                className="gap-1.5"
              >
                <span className="text-xs opacity-70">{t.icon}</span>
                <span className="hidden lg:inline">{t.label}</span>
                <span className="lg:hidden">{t.label.split(" ")[0]}</span>
              </Button>
            ))}
          </nav>
          <div className="ml-auto w-[260px]">
            <SessionCard session={session} onRefresh={refresh} />
          </div>
        </div>
        {/* Mobile nav */}
        <div className="md:hidden border-t border-border overflow-x-auto sharenet-scroll">
          <div className="flex gap-1 px-2 py-2 min-w-max">
            {TABS.map((t) => (
              <Button
                key={t.id}
                variant={tab === t.id ? "default" : "ghost"}
                size="sm"
                onClick={() => setTab(t.id)}
                className="whitespace-nowrap"
              >
                {t.label}
              </Button>
            ))}
          </div>
        </div>
      </header>

      {/* Main content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-6">
        {tab === "overview" && <OverviewTab session={session} loading={loading} setTab={setTab} />}
        {tab === "signup" && <SignupPanel />}
        {tab === "admin" && <AdminPanel session={session} />}
        {tab === "demo" && <DemoPanel onLoggedIn={refresh} />}
        {tab === "protocol" && <ProtocolPanel session={session} />}
        {tab === "mesh" && <MeshPanel />}
        {tab === "architecture" && <ArchitecturePanel />}
        {tab === "spec" && <SpecBrowserPanel />}
      </main>

      {/* Footer */}
      <footer className="mt-auto border-t border-border bg-card/30">
        <div className="max-w-7xl mx-auto px-4 py-4 flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-muted-foreground">
          <div>
            ShareNet 2.0 · Cross-platform, delay-tolerant distributed network ·{" "}
            <span className="text-emerald-400">protocol-first</span>
          </div>
          <div className="flex items-center gap-3 flex-wrap">
            <span>spec/00 §1 — protocol-first rule</span>
            <span>·</span>
            <span>ADR-0001 SQLite sandbox substitution</span>
            <span>·</span>
            <span>ADR-0007 AuthenticatedNodeRecord pipeline</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

function OverviewTab({ session, loading, setTab }: { session: { role: string; isDemo: boolean; email: string } | null; loading: boolean; setTab: (t: Tab) => void }) {
  return (
    <div className="space-y-6">
      {/* Hero */}
      <section className="relative rounded-xl border border-emerald-500/20 p-6 md:p-10 overflow-hidden sharenet-mesh-bg">
        <div className="relative z-10 max-w-3xl">
          <Badge variant="outline" className="text-emerald-300 border-emerald-500/40 mb-3">First Deliverable · Phase 0-2 complete</Badge>
          <h1 className="text-3xl md:text-4xl font-bold tracking-tight mb-3">
            A cross-platform, delay-tolerant distributed network for reaching the real Internet through participating relays and gateways.
          </h1>
          <p className="text-muted-foreground mb-4">
            ShareNet 2.0 is <strong>NOT</strong> &quot;free Internet&quot; — gateway bandwidth has real economic cost. The proof: a device without direct Internet → ShareNet → relay(s) → Internet gateway → real HTTPS server.
          </p>
          <div className="flex gap-2 flex-wrap">
            <Button onClick={() => setTab("protocol")} className="gap-2">
              <span>⛓</span> Open Protocol Playground
            </Button>
            <Button variant="outline" onClick={() => setTab("architecture")} className="gap-2">
              <span>✓</span> Run Architecture Tests
            </Button>
            <Button variant="ghost" onClick={() => setTab("spec")} className="gap-2">
              <span>▤</span> Browse Spec
            </Button>
          </div>
        </div>
      </section>

      {/* Proof diagram */}
      <section className="rounded-xl border border-border p-6">
        <h2 className="text-lg font-semibold mb-3">The Proof (spec/00 §1)</h2>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-2 items-center">
          <ProofNode title="Device" subtitle="without direct Internet" muted />
          <ProofArrow label="via" />
          <ProofNode title="ShareNet" subtitle="VPN/TUN + protocol core" accent />
          <ProofArrow label="multi-hop" />
          <ProofNode title="Internet Gateway" subtitle="→ REAL INTERNET" accent />
        </div>
        <p className="text-xs text-muted-foreground mt-3">
          North-star (spec/00 §39, spec/16): Android with mobile data OFF + Wi-Fi OFF → Chrome → ShareNet VPN/TUN → authenticated multi-hop relay(s) → encrypted circuit → Internet gateway → real HTTPS website.
        </p>
      </section>

      {/* Three-layer architecture (ADR-0013) */}
      <section className="rounded-xl border border-emerald-500/20 p-6">
        <div className="flex items-center gap-2 mb-3">
          <h2 className="text-lg font-semibold">Three-Layer Architecture</h2>
          <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">ADR-0013</Badge>
          <Badge variant="outline" className="text-emerald-300 border-emerald-500/40">machine-enforced</Badge>
        </div>
        <p className="text-sm text-muted-foreground mb-4">
          The web auth system (human accounts, waitlist, admin, demo) lives in the application layer.
          It <strong>may authorize actions</strong> but must never become part of the wire protocol.
          Import boundaries are enforced by architecture tests #21-23.
        </p>
        <div className="space-y-2">
          <LayerBox
            layer="1"
            title="Web Application"
            subtitle="human accounts · waitlist · admin · demo · user roles"
            files="src/app/ · src/lib/auth/ · src/lib/http/ · src/components/"
            imports="may import from layers 1, 2, 3"
            accent="amber"
          />
          <div className="flex items-center gap-2 pl-4">
            <span className="text-muted-foreground text-xs">│ may authorize actions</span>
            <span className="text-emerald-400">↓</span>
          </div>
          <LayerBox
            layer="2"
            title="Service / Control Plane"
            subtitle="node records · sequence floors · gateway policy · architecture tests"
            files="src/lib/sharenet/"
            imports="may import from layer 2, layer 3, @/lib/db — MUST NOT import @/lib/auth/"
            accent="emerald"
          />
          <div className="flex items-center gap-2 pl-4">
            <span className="text-muted-foreground text-xs">│ uses protocol primitives</span>
            <span className="text-emerald-400">↓</span>
          </div>
          <LayerBox
            layer="3"
            title="Protocol Core"
            subtitle="canonical CBOR · Ed25519 · NodeId · NodeAdvertisement · RemoteNodeHint"
            files="reference/"
            imports="pure functions · no DB · no auth · portable to Rust / Go / C"
            accent="emerald"
          />
        </div>
        <p className="text-xs text-muted-foreground mt-3">
          This preserves the spec/00 §2 invariant: a human account is NOT a node identity. The protocol
          core has zero knowledge of sessions, users, or HTTP — so a non-browser implementation can reuse
          it without reimplementing the web auth system.
        </p>
      </section>

      {/* Architectural invariants */}
      <section className="grid md:grid-cols-2 gap-4">
        <Card title="Identity separation (spec/00 §2)">
          <CardContent className="p-4 space-y-2 text-sm">
            <div className="font-semibold">Identity ≠ Identity ≠ Identity</div>
            <div className="text-muted-foreground text-xs">
              Human Identity ≠ Device Identity ≠ Node Identity ≠ Application Identity ≠ Economic Identity.
              <br />
              <strong>NodeId</strong> is permanently bound to one Ed25519 keypair (spec/02 §3, ADR-0003).
            </div>
          </CardContent>
        </Card>
        <Card title="Evidence types (spec/00 §2)">
          <CardContent className="p-4 space-y-2 text-sm">
            <div className="font-semibold">Never silently promote evidence</div>
            <div className="text-muted-foreground text-xs">
              <code>AUTHENTICATED</code> ≠ <code>OBSERVED</code> ≠ <code>REPORTED</code> ≠ <code>DERIVED</code> ≠ <code>INFERRED</code>.
              <br />
              Each evidence category is a distinct type (ADR-0005).
            </div>
          </CardContent>
        </Card>
        <Card title="Gateway semantics (spec/00 §2)">
          <CardContent className="p-4 space-y-2 text-sm">
            <div className="font-semibold">Capability ≠ Authorization</div>
            <div className="text-muted-foreground text-xs">
              GatewayCapability ≠ Policy ≠ Authorization ≠ Capacity ≠ Measurement.
              <br />
              INTERNET_GATEWAY capability does NOT mean automatic usable gateway (ADR-0011).
            </div>
          </CardContent>
        </Card>
        <Card title="Routing (spec/00 §2)">
          <CardContent className="p-4 space-y-2 text-sm">
            <div className="font-semibold">Discovery ≠ Route ≠ Circuit</div>
            <div className="text-muted-foreground text-xs">
              Discovery ≠ Path Validation ≠ Route Construction ≠ Circuit Establishment.
              <br />
              Distance hints are <strong>discovery metadata</strong>, never executable routing instructions (spec/07).
            </div>
          </CardContent>
        </Card>
      </section>

      {/* Status row */}
      <section className="grid md:grid-cols-3 gap-4">
        <StatusCard
          title="Authenticated session"
          status={loading ? "loading" : session ? "active" : "none"}
          detail={session ? `${session.email} · ${session.role}${session.isDemo ? " (demo)" : ""}` : "No session. Use demo quick-login or sign in."}
          action={session ? undefined : { label: "Quick demo login", onClick: () => setTab("demo") }}
        />
        <StatusCard
          title="Protocol foundation"
          status="active"
          detail="Canonical CBOR + Ed25519 + NodeId + NodeAdvertisement + persistent sequence floors + RemoteNodeHint"
          action={{ label: "Open playground", onClick: () => setTab("protocol") }}
        />
        <StatusCard
          title="Architecture regression tests"
          status="active"
          detail="20 executable tests: 10 first tests (spec/00 §32) + forbidden-pipeline guards (spec/00 §31)"
          action={{ label: "Run tests", onClick: () => setTab("architecture") }}
        />
      </section>

      {/* What is and is NOT ShareNet */}
      <section className="grid md:grid-cols-2 gap-4">
        <Card>
          <CardContent className="p-4 space-y-2">
            <div className="font-semibold text-emerald-400">ShareNet IS</div>
            <ul className="text-sm space-y-1 text-muted-foreground list-disc list-inside">
              <li>A delay-tolerant distributed network protocol</li>
              <li>Cross-platform (Linux / Windows / macOS / Android / iOS — spec/16)</li>
              <li>Identity-bound to Ed25519 keys with deterministic NodeIds</li>
              <li>A relay + gateway model with mandatory SSRF/quota guards</li>
              <li>Open: any conformant implementation can interoperate</li>
            </ul>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="p-4 space-y-2">
            <div className="font-semibold text-destructive">ShareNet is NOT</div>
            <ul className="text-sm space-y-1 text-muted-foreground list-disc list-inside">
              <li>Free Internet — gateway bandwidth has real economic cost</li>
              <li>A blockchain — Civic Points are initially internal credits (spec/12)</li>
              <li>A trust-on-first-use network — RemoteNodeHints cannot become AuthenticatedNodeRecords (spec/06 §3)</li>
              <li>A topology-graph + Dijkstra router — distance hints are metadata, not routes (spec/07)</li>
              <li>An open proxy — gateways enforce destination policy + SSRF + quota + revocation (spec/09)</li>
            </ul>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}

function ProofNode({ title, subtitle, accent, muted }: { title: string; subtitle: string; accent?: boolean; muted?: boolean }) {
  return (
    <div className={`rounded-lg border p-3 text-center ${accent ? "border-emerald-500/40 bg-emerald-500/10" : muted ? "border-border bg-muted/20" : "border-border"}`}>
      <div className={`font-medium text-sm ${accent ? "text-emerald-300" : ""}`}>{title}</div>
      <div className="text-xs text-muted-foreground mt-1">{subtitle}</div>
    </div>
  );
}

function LayerBox({ layer, title, subtitle, files, imports, accent }: { layer: string; title: string; subtitle: string; files: string; imports: string; accent: "amber" | "emerald" }) {
  const borderClass = accent === "amber" ? "border-amber-500/30 bg-amber-500/5" : "border-emerald-500/30 bg-emerald-500/5";
  const labelClass = accent === "amber" ? "text-amber-400 border-amber-500/40" : "text-emerald-300 border-emerald-500/40";
  return (
    <div className={`rounded-lg border ${borderClass} p-3`}>
      <div className="flex items-center gap-2 flex-wrap mb-1">
        <Badge variant="outline" className={labelClass}>Layer {layer}</Badge>
        <span className="font-medium text-sm">{title}</span>
      </div>
      <div className="text-xs text-muted-foreground">{subtitle}</div>
      <div className="text-xs font-mono text-muted-foreground/70 mt-1">{files}</div>
      <div className="text-xs mt-1"><span className="text-muted-foreground">imports: </span><span className={accent === "amber" ? "text-amber-300" : "text-emerald-300"}>{imports}</span></div>
    </div>
  );
}
function ProofArrow({ label }: { label: string }) {
  return (
    <div className="flex flex-col items-center justify-center text-emerald-400">
      <div className="text-2xl">→</div>
      <div className="text-xs text-muted-foreground">{label}</div>
    </div>
  );
}

function Card({ title, children }: { title?: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-border bg-card">
      {title && <div className="px-4 pt-3 text-sm font-semibold text-muted-foreground">{title}</div>}
      {children}
    </div>
  );
}
function CardContent({ children, className = "" }: { children: React.ReactNode; className?: string }) {
  return <div className={className}>{children}</div>;
}

function StatusCard({ title, status, detail, action }: { title: string; status: "active" | "none" | "loading"; detail: string; action?: { label: string; onClick: () => void } }) {
  const color = status === "active" ? "text-emerald-400" : status === "loading" ? "text-amber-400" : "text-muted-foreground";
  const dot = status === "active" ? "●" : status === "loading" ? "◐" : "○";
  return (
    <div className="rounded-xl border border-border bg-card p-4">
      <div className="flex items-center gap-2 mb-1">
        <span className={`${color} text-lg`}>{dot}</span>
        <span className="font-medium text-sm">{title}</span>
      </div>
      <div className="text-xs text-muted-foreground mb-2">{detail}</div>
      {action && <Button size="sm" variant="outline" onClick={action.onClick}>{action.label}</Button>}
    </div>
  );
}
