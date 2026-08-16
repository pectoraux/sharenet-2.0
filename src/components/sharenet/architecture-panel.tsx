"use client";

import { useEffect, useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";

interface TestResult {
  id: number;
  name: string;
  category: "PROTOCOL" | "ARCHITECTURE" | "SECURITY";
  passed: boolean;
  description: string;
  expected: string;
  actual: string;
  durationMs: number;
}
interface SuiteResult {
  totalTests: number;
  passed: number;
  failed: number;
  results: TestResult[];
  ranAt: string;
  durationMs: number;
  spec: string;
}

export function ArchitecturePanel() {
  const [result, setResult] = useState<SuiteResult | null>(null);
  const [loading, setLoading] = useState(false);

  const run = useCallback(async () => {
    setLoading(true);
    const r = await api<SuiteResult>("/api/sharenet/architecture/summary");
    setLoading(false);
    if (r.ok && r.data) {
      setResult(r.data);
      if (r.data.failed === 0) toast.success(`All ${r.data.passed} architecture tests pass`);
      else toast.error(`${r.data.failed} test(s) failing`);
    } else toast.error(r.error ?? "Test run failed");
  }, []);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (cancelled) return;
      await run();
    })();
    return () => { cancelled = true; };
  }, [run]);

  const passing = result?.passed ?? 0;
  const total = result?.totalTests ?? 0;
  const allPass = result !== null && result.failed === 0;

  return (
    <Card className={allPass ? "border-emerald-500/40" : "border-destructive/40"}>
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          Architecture Regression Tests
          {result && (
            <Badge variant={allPass ? "outline" : "destructive"} className={allPass ? "text-emerald-300 border-emerald-500/40" : ""}>
              {passing}/{total} passing
            </Badge>
          )}
          {allPass && <span className="text-emerald-400 text-2xl">✓</span>}
        </CardTitle>
        <CardDescription>
          The 10 first tests from spec/00 §32 + the forbidden-pipeline guards from spec/00 §31.
          These run as executable tests; CI must fail if any forbidden pipeline is permitted.
          Per ADR-0010, cannot rely on code review alone.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center gap-3 flex-wrap">
          <Button onClick={run} disabled={loading} size="sm">{loading ? "Running…" : "Run suite"}</Button>
          {result && (
            <div className="text-xs text-muted-foreground">
              {result.durationMs}ms · ran at {new Date(result.ranAt).toLocaleTimeString()}
            </div>
          )}
        </div>
        <div className="grid gap-2 max-h-[600px] overflow-y-auto sharenet-scroll">
          {result?.results.map((t) => (
            <div key={t.id} className={`border rounded-md p-3 ${t.passed ? "border-emerald-500/30 bg-emerald-500/5" : "border-destructive/40 bg-destructive/5"}`}>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge variant="outline" className="text-xs">{t.category}</Badge>
                <span className="font-medium text-sm">{t.id}. {t.name}</span>
                <span className="ml-auto text-xs">
                  {t.passed ? <span className="text-emerald-400">PASS ✓</span> : <span className="text-destructive">FAIL ✗</span>}
                </span>
              </div>
              <div className="text-xs text-muted-foreground mt-1">{t.description}</div>
              <div className="text-xs mt-1">
                <span className="text-muted-foreground">expected: </span><code className="text-emerald-300">{t.expected}</code>
              </div>
              <div className="text-xs">
                <span className="text-muted-foreground">actual: </span><code className={t.passed ? "text-emerald-300" : "text-destructive"}>{t.actual}</code>
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
