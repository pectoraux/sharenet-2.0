/**
 * ShareNet 2.0 — GATE-09 Tests: Linux transparent networking.
 *
 * Per GATE-09 requirements:
 *   - local proxy/TUN policy
 *   - DNS leak prevention
 *   - process lifecycle and kill-switch behavior
 *
 * Browser integration test (ordinary Linux browser reaches real HTTPS through
 * ShareNet) is DEFERRED — it requires the full real-process stack (3-message
 * handshake → circuit → gateway forwarding → TUN device) wired up end-to-end
 * with real processes. The unit tests prove the policy/lifecycle correctness.
 */

import { describe, test, expect } from "bun:test";
import {
  defaultTunPolicy,
  wouldDnsLeak,
  wouldBypassShareNet,
  KillSwitch,
  ProcessLifecycle,
  defaultLinuxTunConfig,
  PLATFORM_PROTOCOL_SEMANTICS_FORBIDDEN,
  type TunPolicy,
  type ProcessState,
} from "@reference/platform/tun-adapter";

describe("GATE-09: Linux transparent networking", () => {
  // --- 1. TUN policy defaults ---
  test("default TUN policy routes all traffic through ShareNet", () => {
    const policy = defaultTunPolicy();
    expect(policy.routeRanges).toContain("0.0.0.0/0");
    expect(policy.killSwitch).toBe(true);
    expect(policy.blockIpv6).toBe(true);
    expect(policy.dnsServers.length).toBeGreaterThan(0);
  });

  // --- 2. DNS leak prevention: system DNS rejected ---
  test("DNS query to system resolver is rejected (leak)", () => {
    const policy = defaultTunPolicy();
    const result = wouldDnsLeak("8.8.8.8", "A", policy); // Google DNS, not ShareNet
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("not in ShareNet DNS list");
  });

  // --- 3. DNS leak prevention: ShareNet DNS accepted ---
  test("DNS query to ShareNet DNS proxy is accepted", () => {
    const policy = defaultTunPolicy();
    const result = wouldDnsLeak("10.8.0.53", "A", policy);
    expect(result.ok).toBe(true);
  });

  // --- 4. DNS leak prevention: IPv6 AAAA blocked ---
  test("AAAA (IPv6) DNS query is blocked when blockIpv6=true", () => {
    const policy = defaultTunPolicy();
    const result = wouldDnsLeak("10.8.0.53", "AAAA", policy);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).toContain("IPv6 DNS leak prevention");
  });

  // --- 5. DNS leak prevention: IPv6 AAAA allowed when blockIpv6=false ---
  test("AAAA query allowed when blockIpv6=false", () => {
    const policy: TunPolicy = { ...defaultTunPolicy(), blockIpv6: false };
    const result = wouldDnsLeak("10.8.0.53", "AAAA", policy);
    expect(result.ok).toBe(true);
  });

  // --- 6. Bypass: no bypass domains → all through ShareNet ---
  test("no bypass domains → traffic goes through ShareNet", () => {
    const policy = defaultTunPolicy();
    const result = wouldBypassShareNet("example.com:443", policy);
    expect(result.bypass).toBe(false);
  });

  // --- 7. Bypass: matching domain bypasses ShareNet ---
  test("matching bypass domain → traffic bypasses ShareNet", () => {
    const policy: TunPolicy = { ...defaultTunPolicy(), bypassDomains: ["localhost"] };
    const result = wouldBypassShareNet("localhost:8080", policy);
    expect(result.bypass).toBe(true);
  });

  test("wildcard bypass domain matches subdomain", () => {
    const policy: TunPolicy = { ...defaultTunPolicy(), bypassDomains: ["*.local"] };
    const result = wouldBypassShareNet("printer.local:9100", policy);
    expect(result.bypass).toBe(true);
  });

  // --- 8. Kill-switch: TUN down → traffic blocked ---
  test("kill-switch blocks traffic when TUN goes down", () => {
    const ks = new KillSwitch();
    ks.enable();
    ks.onTunStart();
    expect(ks.isBlocked()).toBe(false); // TUN active → not blocked

    ks.onTunFailure(); // TUN fails
    expect(ks.isBlocked()).toBe(true); // traffic blocked
  });

  // --- 9. Kill-switch: TUN gracefully stopped → blocked ---
  test("kill-switch blocks traffic on graceful TUN stop", () => {
    const ks = new KillSwitch();
    ks.enable();
    ks.onTunStart();
    expect(ks.isBlocked()).toBe(false);

    ks.onTunStop(); // graceful stop
    expect(ks.isBlocked()).toBe(true); // still blocked
  });

  // --- 10. Kill-switch: disabled → no blocking ---
  test("kill-switch disabled → traffic not blocked on TUN stop", () => {
    const ks = new KillSwitch();
    // NOT enabling kill-switch
    ks.onTunStart();
    ks.onTunStop();
    expect(ks.isBlocked()).toBe(false);
  });

  // --- 11. Kill-switch: re-enabled after TUN starts ---
  test("kill-switch: TUN restart clears block", () => {
    const ks = new KillSwitch();
    ks.enable();
    ks.onTunStart();
    ks.onTunFailure();
    expect(ks.isBlocked()).toBe(true);

    ks.onTunStart(); // TUN restarts
    expect(ks.isBlocked()).toBe(false);
  });

  // --- 12. Process lifecycle: valid transitions ---
  test("process lifecycle: STOPPED → STARTING → RUNNING", () => {
    const lc = new ProcessLifecycle();
    expect(lc.getState()).toBe("STOPPED");

    expect(lc.transition("STARTING", "user initiated")).toBe(true);
    expect(lc.getState()).toBe("STARTING");

    expect(lc.transition("RUNNING", "tun up")).toBe(true);
    expect(lc.getState()).toBe("RUNNING");
  });

  // --- 13. Process lifecycle: invalid transition rejected ---
  test("process lifecycle: invalid transition rejected", () => {
    const lc = new ProcessLifecycle();
    expect(lc.transition("RUNNING", "skip startup")).toBe(false); // STOPPED → RUNNING invalid
    expect(lc.getState()).toBe("STOPPED");
  });

  // --- 14. Process lifecycle: crash → auto-restart ---
  test("process lifecycle: crash triggers auto-restart", () => {
    const lc = new ProcessLifecycle();
    lc.transition("STARTING", "user");
    lc.transition("RUNNING", "tun up");
    lc.transition("CRASHED", "segfault");

    // Should auto-restart
    expect(lc.getState()).toBe("STARTING");
    expect(lc.getRestartCount()).toBe(1);
  });

  // --- 15. Process lifecycle: max restarts → stays CRASHED ---
  test("process lifecycle: max restarts → stays crashed", () => {
    const lc = new ProcessLifecycle();
    lc.transition("STARTING", "user");
    lc.transition("RUNNING", "tun up");

    // Crash 3 times (maxRestarts)
    for (let i = 0; i < 3; i++) {
      lc.transition("CRASHED", `crash ${i + 1}`);
      if (lc.getState() === "STARTING") {
        lc.transition("RUNNING", "recovered");
      }
    }
    // 4th crash → no more restarts
    lc.transition("CRASHED", "crash 4");
    expect(lc.getState()).toBe("CRASHED"); // stays crashed
    expect(lc.getRestartCount()).toBe(3);
  });

  // --- 16. Process lifecycle: kill-switch integration ---
  test("process lifecycle: RUNNING → kill-switch not blocked; CRASHED → blocked", () => {
    const lc = new ProcessLifecycle();
    lc.getKillSwitch().enable();

    lc.transition("STARTING", "user");
    lc.transition("RUNNING", "tun up");
    expect(lc.getKillSwitch().isBlocked()).toBe(false);

    lc.transition("CRASHED", "segfault");
    expect(lc.getKillSwitch().isBlocked()).toBe(true);
  });

  // --- 17. Linux TUN config defaults ---
  test("Linux TUN config has correct defaults", () => {
    const config = defaultLinuxTunConfig();
    expect(config.interfaceName).toBe("sharenet0");
    expect(config.address).toBe("10.8.0.1");
    expect(config.mtu).toBe(1400);
    expect(config.routeRanges).toContain("0.0.0.0/0");
  });

  // --- 18. Platform protocol semantics guard ---
  test("PLATFORM_PROTOCOL_SEMANTICS_FORBIDDEN throws", () => {
    expect(() => PLATFORM_PROTOCOL_SEMANTICS_FORBIDDEN("linux", "custom-routing-semantic")).toThrow();
  });

  // --- 19. Process lifecycle: DEGRADED state ---
  test("process lifecycle: RUNNING → DEGRADED → RUNNING (recovery)", () => {
    const lc = new ProcessLifecycle();
    lc.transition("STARTING", "user");
    lc.transition("RUNNING", "tun up");
    lc.transition("DEGRADED", "high latency");
    expect(lc.getState()).toBe("DEGRADED");

    lc.transition("RUNNING", "latency recovered");
    expect(lc.getState()).toBe("RUNNING");
  });

  // --- 20. Process lifecycle: graceful shutdown ---
  test("process lifecycle: RUNNING → STOPPING → STOPPED", () => {
    const lc = new ProcessLifecycle();
    lc.transition("STARTING", "user");
    lc.transition("RUNNING", "tun up");
    lc.transition("STOPPING", "user shutdown");
    expect(lc.getState()).toBe("STOPPING");

    lc.transition("STOPPED", "cleanup complete");
    expect(lc.getState()).toBe("STOPPED");
  });
});
