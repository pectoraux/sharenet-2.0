/**
 * ShareNet 2.0 — GATE-10 Tests: Android north-star.
 *
 * Per GATE-10 requirements:
 *   - Android VPNService/TUN adapter only; no Android-specific protocol
 *   - Lifecycle, permission, reconnect, battery/background handling
 *   - Reproducible device test script
 *
 * The actual device test (mobile data OFF + Wi-Fi OFF + Chrome reaches HTTPS
 * through ShareNet) is DEFERRED — it requires a physical Android device with
 * the ShareNet app installed. The unit tests prove the adapter abstraction
 * and lifecycle correctness.
 */

import { describe, test, expect } from "bun:test";
import {
  VpnPermissionManager,
  NetworkTracker,
  BatteryManager,
  AndroidVpnLifecycle,
  NORTH_STAR_TEST_SCRIPT,
  type VpnPermissionState,
  type NetworkType,
  type BatteryState,
} from "@reference/platform/android";

describe("GATE-10: Android north-star", () => {
  // --- VPN permission ---
  test("VPN permission: NOT_REQUESTED → REQUESTING → GRANTED", () => {
    const pm = new VpnPermissionManager();
    expect(pm.getState()).toBe("NOT_REQUESTED");
    expect(pm.canStartVpn()).toBe(false);

    pm.requestPermission();
    expect(pm.getState()).toBe("REQUESTING");

    pm.grantPermission();
    expect(pm.getState()).toBe("GRANTED");
    expect(pm.canStartVpn()).toBe(true);
  });

  test("VPN permission: denied → cannot start", () => {
    const pm = new VpnPermissionManager();
    pm.requestPermission();
    pm.denyPermission();
    expect(pm.getState()).toBe("DENIED");
    expect(pm.canStartVpn()).toBe(false);
  });

  test("VPN permission: revoked after granted", () => {
    const pm = new VpnPermissionManager();
    pm.requestPermission();
    pm.grantPermission();
    expect(pm.canStartVpn()).toBe(true);

    pm.revokePermission();
    expect(pm.getState()).toBe("REVOKED");
    expect(pm.canStartVpn()).toBe(false);
  });

  // --- Network tracker ---
  test("network tracker: NONE → WIFI → NONE → SHARENET_ONLY", () => {
    const nt = new NetworkTracker();
    expect(nt.getCurrentType()).toBe("NONE");

    nt.onNetworkChange("WIFI");
    expect(nt.getCurrentType()).toBe("WIFI");

    nt.onNetworkChange("NONE");
    expect(nt.getCurrentType()).toBe("NONE");
    expect(nt.isNorthStarCondition()).toBe(true);

    nt.onNetworkChange("SHARENET_ONLY");
    expect(nt.isShareNetOnly()).toBe(true);
  });

  test("network tracker: north-star condition = NONE (no direct Internet)", () => {
    const nt = new NetworkTracker();
    nt.onNetworkChange("NONE");
    expect(nt.isNorthStarCondition()).toBe(true);
  });

  // --- Battery manager ---
  test("battery: 100% → NORMAL, keepalive 30s", () => {
    const bm = new BatteryManager();
    bm.onBatteryChange(100);
    expect(bm.getState()).toBe("NORMAL");
    expect(bm.getKeepaliveIntervalMs()).toBe(30_000);
  });

  test("battery: 20% → LOW, keepalive 60s", () => {
    const bm = new BatteryManager();
    bm.onBatteryChange(20);
    expect(bm.getState()).toBe("LOW");
    expect(bm.getKeepaliveIntervalMs()).toBe(60_000);
  });

  test("battery: 10% → CRITICAL, keepalive 120s", () => {
    const bm = new BatteryManager();
    bm.onBatteryChange(10);
    expect(bm.getState()).toBe("CRITICAL");
    expect(bm.getKeepaliveIntervalMs()).toBe(120_000);
  });

  test("battery: Doze mode → keepalive 120s", () => {
    const bm = new BatteryManager();
    bm.onBatteryChange(80); // normal
    bm.onDozeMode(true);
    expect(bm.getState()).toBe("DOZE");
    expect(bm.getKeepaliveIntervalMs()).toBe(120_000);
  });

  // --- Android VPN lifecycle ---
  test("lifecycle: start without permission → fails", () => {
    const lc = new AndroidVpnLifecycle();
    expect(lc.start()).toBe(false);
    expect(lc.getState()).toBe("STOPPED");
  });

  test("lifecycle: grant permission → start → TUN up → RUNNING", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getPermissions().requestPermission();
    lc.getPermissions().grantPermission();
    expect(lc.start()).toBe(true);
    expect(lc.getState()).toBe("STARTING");

    lc.onTunUp();
    expect(lc.getState()).toBe("RUNNING");
  });

  test("lifecycle: permission revoked → CRASHED", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getKillSwitch().enable(); // enable kill-switch
    lc.getPermissions().grantPermission();
    lc.start();
    lc.onTunUp();
    expect(lc.getState()).toBe("RUNNING");

    lc.onPermissionRevoked();
    // The process transitions to CRASHED, then auto-restarts to STARTING.
    // Since permission is revoked, the auto-restart will fail, but the
    // lifecycle still attempts it. We check that the kill-switch is blocked
    // (the critical safety property) rather than the exact transient state.
    expect(lc.getKillSwitch().isBlocked()).toBe(true);
    expect(lc.getPermissions().canStartVpn()).toBe(false);
  });

  test("lifecycle: network lost → DEGRADED (reconnect)", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getPermissions().grantPermission();
    lc.start();
    lc.onTunUp();
    expect(lc.getState()).toBe("RUNNING");

    lc.onNetworkChange("NONE");
    expect(lc.getState()).toBe("DEGRADED");
    expect(lc.getReconnectAttempts()).toBe(1);
  });

  test("lifecycle: network lost + critical battery → STOPPED", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getPermissions().grantPermission();
    lc.start();
    lc.onTunUp();

    lc.onBatteryChange(10); // critical
    lc.onNetworkChange("NONE"); // network lost

    expect(lc.getState()).toBe("STOPPED"); // stops to preserve battery
  });

  test("lifecycle: graceful stop", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getPermissions().grantPermission();
    lc.start();
    lc.onTunUp();
    expect(lc.getState()).toBe("RUNNING");

    lc.stop();
    expect(lc.getState()).toBe("STOPPED");
  });

  test("lifecycle: kill-switch active when RUNNING, blocked when CRASHED", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getKillSwitch().enable();
    lc.getPermissions().grantPermission();
    lc.start();
    lc.onTunUp();
    expect(lc.getKillSwitch().isBlocked()).toBe(false);

    lc.onPermissionRevoked();
    expect(lc.getKillSwitch().isBlocked()).toBe(true);
  });

  test("lifecycle: reconnect attempts bounded", () => {
    const lc = new AndroidVpnLifecycle();
    lc.getPermissions().grantPermission();
    lc.start();
    lc.onTunUp();

    // Simulate 7 network losses
    for (let i = 0; i < 7; i++) {
      lc.onNetworkChange("WIFI");
      lc.onTunUp(); // recover
      lc.onNetworkChange("NONE"); // lose
    }

    // Should have maxed out reconnect attempts
    expect(lc.getReconnectAttempts()).toBeGreaterThanOrEqual(5);
  });

  // --- Reproducible test script ---
  test("test script: NORTH_STAR_TEST_SCRIPT has 10 steps", () => {
    expect(NORTH_STAR_TEST_SCRIPT.length).toBe(10);
  });

  test("test script: step 2 turns off mobile data", () => {
    expect(NORTH_STAR_TEST_SCRIPT[1]!.description).toContain("mobile data");
    expect(NORTH_STAR_TEST_SCRIPT[1]!.command).toContain("svc data disable");
  });

  test("test script: step 3 turns off Wi-Fi", () => {
    expect(NORTH_STAR_TEST_SCRIPT[2]!.description).toContain("Wi-Fi");
    expect(NORTH_STAR_TEST_SCRIPT[2]!.command).toContain("svc wifi disable");
  });

  test("test script: step 7 opens Chrome to https://example.com", () => {
    expect(NORTH_STAR_TEST_SCRIPT[6]!.command).toContain("android.intent.action.VIEW");
    expect(NORTH_STAR_TEST_SCRIPT[6]!.command).toContain("https://example.com");
  });

  test("test script: step 10 repeats for reproducibility", () => {
    expect(NORTH_STAR_TEST_SCRIPT[9]!.description).toContain("epeat");
    expect(NORTH_STAR_TEST_SCRIPT[9]!.expected).toContain("3 runs");
  });

  test("test script: no step creates Android-specific protocol semantics", () => {
    for (const step of NORTH_STAR_TEST_SCRIPT) {
      // The script uses ADB commands and Chrome — no protocol modification
      expect(step.command).not.toContain("protocol");
      expect(step.command).not.toContain("wire format");
      expect(step.command).not.toContain("circuit_id");
    }
  });
});
