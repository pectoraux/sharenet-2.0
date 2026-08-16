"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/sharenet/fetch";
import { toast } from "sonner";

const ROLES = [
  { value: "USER", label: "User" },
  { value: "RELAY_OPERATOR", label: "Relay Operator" },
  { value: "GATEWAY_OPERATOR", label: "Gateway Operator" },
  { value: "CONTENT_PROVIDER", label: "Content Provider" },
  { value: "STORAGE_PROVIDER", label: "Storage Provider" },
  { value: "COMPUTE_PROVIDER", label: "Compute Provider" },
];

export function SignupPanel() {
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [role, setRole] = useState("USER");
  const [notes, setNotes] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string; status?: string } | null>(null);

  async function submit() {
    if (!email) { toast.error("Email is required"); return; }
    setSubmitting(true);
    const r = await api("/api/sharenet/waitlist/signup", {
      method: "POST",
      body: JSON.stringify({ email, name: name || undefined, requestedUserType: role, notes: notes || undefined }),
    });
    setSubmitting(false);
    if (r.ok && r.data) {
      const d = r.data as { ok: boolean; status: string; message: string; alreadySubmitted?: boolean };
      setResult({ ok: true, message: d.message, status: d.status });
      toast.success(d.message);
    } else {
      setResult({ ok: false, message: r.error ?? "Submission failed" });
      toast.error(r.error ?? "Submission failed");
    }
  }

  return (
    <Card className="border-emerald-500/20">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <span className="text-emerald-400">⟁</span> Waitlist Signup
        </CardTitle>
        <CardDescription>
          Per spec/00 §7: public signup does NOT create an active user account.
          Your request enters a PENDING waitlist. An administrator reviews and
          decides whether to create a real account.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-2">
          <Label htmlFor="signup-email">Email <span className="text-destructive">*</span></Label>
          <Input id="signup-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="signup-name">Name (optional)</Label>
          <Input id="signup-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Your name" />
        </div>
        <div className="grid gap-2">
          <Label>Requested user type</Label>
          <Select value={role} onValueChange={setRole}>
            <SelectTrigger><SelectValue /></SelectTrigger>
            <SelectContent>
              {ROLES.map((r) => <SelectItem key={r.value} value={r.value}>{r.label}</SelectItem>)}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="signup-notes">Notes (optional)</Label>
          <Input id="signup-notes" value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="Why do you want to join?" />
        </div>
        <Button onClick={submit} disabled={submitting} className="w-full">
          {submitting ? "Submitting…" : "Join waitlist"}
        </Button>
        {result && (
          <div className={`text-sm rounded-md p-3 border ${result.ok ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300" : "border-destructive/30 bg-destructive/10 text-destructive"}`}>
            <div className="flex items-center gap-2">
              {result.ok ? <Badge variant="outline" className="border-emerald-500/40 text-emerald-300">{result.status}</Badge> : <Badge variant="destructive">ERROR</Badge>}
              <span>{result.message}</span>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
