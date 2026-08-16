"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/sharenet/fetch";

interface DocEntry {
  name: string;
  path: string;
  sizeBytes: number;
  preview: string;
}

export function SpecBrowserPanel() {
  const [spec, setSpec] = useState<DocEntry[]>([]);
  const [adr, setAdr] = useState<DocEntry[]>([]);
  const [selected, setSelected] = useState<{ path: string; content: string } | null>(null);
  const [loading, setLoading] = useState(true);

  const reload = useCallback(async () => {
    const r = await api<{ spec: DocEntry[]; adr: DocEntry[] }>("/api/sharenet/spec");
    if (r.ok && r.data) { setSpec(r.data.spec); setAdr(r.data.adr); }
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

  async function openDoc(path: string) {
    // Use a relative fetch (read markdown directly from the public/ tree is not available
    // because spec/ and adr/ are not in public/). Instead, we display the preview we already have.
    // For a longer view, the user can read the file directly in the repo.
    const entry = [...spec, ...adr].find((d) => d.path === path);
    if (entry) {
      // Fetch the full file via a tiny server-side route would be cleanest; for now we
      // show the preview (first 600 chars) which is enough for the dashboard.
      setSelected({ path: entry.path, content: entry.preview + "\n\n[... truncated — view full file in repository: " + entry.path + "]" });
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Normative Specification <Badge variant="outline" className="ml-2">{spec.length} files</Badge></CardTitle>
          <CardDescription>The spec/ directory is AUTHORITATIVE. The implementation is subordinate to it. Per spec/00 §3 protocol-first rule.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 max-h-[400px] overflow-y-auto sharenet-scroll">
          {loading && <div className="text-sm text-muted-foreground">Loading…</div>}
          {spec.map((d) => (
            <button
              key={d.path}
              onClick={() => openDoc(d.path)}
              className="text-left border border-border rounded-md p-2 hover:bg-muted/30 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-emerald-300">{d.name}</span>
                <span className="text-xs text-muted-foreground ml-auto">{Math.round(d.sizeBytes / 1024)}KB</span>
              </div>
              <div className="text-xs text-muted-foreground mt-1 line-clamp-2">{d.preview.split("\n").slice(0, 2).join(" ")}</div>
            </button>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Architecture Decision Records <Badge variant="outline" className="ml-2">{adr.length} files</Badge></CardTitle>
          <CardDescription>ADRs record WHY decisions were made. Standard Michael Nygard template: Status, Context, Decision, Consequences, Alternatives.</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 max-h-[400px] overflow-y-auto sharenet-scroll">
          {adr.map((d) => (
            <button
              key={d.path}
              onClick={() => openDoc(d.path)}
              className="text-left border border-border rounded-md p-2 hover:bg-muted/30 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs text-emerald-300">{d.name}</span>
                <span className="text-xs text-muted-foreground ml-auto">{Math.round(d.sizeBytes / 1024)}KB</span>
              </div>
              <div className="text-xs text-muted-foreground mt-1 line-clamp-2">{d.preview.split("\n").slice(0, 2).join(" ")}</div>
            </button>
          ))}
        </CardContent>
      </Card>

      {selected && (
        <Card>
          <CardHeader>
            <CardTitle className="font-mono text-sm">{selected.path}</CardTitle>
          </CardHeader>
          <CardContent>
            <pre className="text-xs whitespace-pre-wrap font-mono p-3 bg-muted/30 rounded max-h-[400px] overflow-y-auto sharenet-scroll">{selected.content}</pre>
            <Button variant="ghost" size="sm" className="mt-2" onClick={() => setSelected(null)}>Close</Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
