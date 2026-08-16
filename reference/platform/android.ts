/**
 * ShareNet 2.0 — Android VPNService Adapter (GATE-10).
 *
 * Per spec/16-platforms.md §3 and GATE-10 requirements:
 *
 *   - Android VPNService/TUN adapter only; no Android-specific protocol
 *   - Lifecycle, permission, reconnect, battery/background handling
 *   - Real relay/gateway topology
 *   - Reproducible device test script
 *
 *   Exit:
 *     Android mobile data OFF
 *     Internet Wi-Fi OFF
 *     ordinary Chrome reaches real HTTPS through ShareNet
 *     repeated successful runs documented with logs and evidence
 *
 * Per spec/16 §1: "Platform adapters must NOT create platform-specific
 * protocol semantics. The protocol core is platform-agnostic."
 *
 * The Android adapter uses the SAME TunAdapter interface from GATE-09
 * (reference/platform/tun-adapter.ts). Android's VPNService provides the
 * TUN device; the protocol core is identical to Linux.
 *
 * This module adds Android-specific lifecycle concerns: VPN permission
 * state, reconnect on network change, battery/background behavior.
 */

import {
  type TunPolicy,
  KillSwitch,
  ProcessLifecycle,
  type ProcessState,
} from "./tun-adapter";

// -----------------------------------------------------------------------
// Android VPN permission state
// -----------------------------------------------------------------------

/**
 * Android VPN permission state.
 *
 * On Android, the user must grant VPN permission via a system dialog
 * (VPNService.prepare()). The permission can be revoked at any time by
 * the user or the system. The adapter MUST handle permission denial
 * gracefully — it cannot start the TUN without permission.
 */
export type VpnPermissionState =
  | "NOT_REQUESTED"     // permission has not been requested yet
  | "REQUESTING"        // system dialog is showing
  | "GRANTED"           // user granted permission
  | "DENIED"            // user denied permission
  | "REVOKED";          // system revoked permission (e.g. another VPN app started)

export interface PermissionEvent {
  oldState: VpnPermissionState;
  newState: VpnPermissionState;
  timestamp: number;
  reason: string;
}

/**
 * VPN permission manager for Android.
 */
export class VpnPermissionManager {
  private state: VpnPermissionState = "NOT_REQUESTED";
  private events: PermissionEvent[] = [];

  getState(): VpnPermissionState {
    return this.state;
  }

  /** Called when the system dialog starts showing. */
  requestPermission(now: number = Date.now()): void {
    this.transition("REQUESTING", "system dialog shown", now);
  }

  /** Called when the user grants permission. */
  grantPermission(now: number = Date.now()): void {
    this.transition("GRANTED", "user granted VPN permission", now);
  }

  /** Called when the user denies permission. */
  denyPermission(now: number = Date.now()): void {
    this.transition("DENIED", "user denied VPN permission", now);
  }

  /** Called when the system revokes permission (another VPN app took over). */
  revokePermission(now: number = Date.now()): void {
    this.transition("REVOKED", "system revoked (another VPN app started)", now);
  }

  /** True if the VPN can be started (permission is GRANTED). */
  canStartVpn(): boolean {
    return this.state === "GRANTED";
  }

  getEvents(): readonly PermissionEvent[] {
    return this.events;
  }

  private transition(newState: VpnPermissionState, reason: string, now: number): void {
    if (this.state === newState) return;
    this.events.push({ oldState: this.state, newState, timestamp: now, reason });
    if (this.events.length > 100) this.events.shift();
    this.state = newState;
  }
}

// -----------------------------------------------------------------------
// Network connectivity state (Android)
// -----------------------------------------------------------------------

/**
 * Android network connectivity state.
 *
 * The adapter MUST handle network changes (Wi-Fi ↔ mobile data ↔ none)
 * and reconnect the ShareNet circuit when connectivity is restored.
 *
 * Per GATE-10: the north-star test requires mobile data OFF + Wi-Fi OFF,
 * meaning the only connectivity is through ShareNet itself. But the adapter
 * also needs to handle the transition states.
 */
export type NetworkType = "WIFI" | "MOBILE_DATA" | "NONE" | "SHARENET_ONLY";

export interface NetworkChangeEvent {
  oldType: NetworkType;
  newType: NetworkType;
  timestamp: number;
}

/**
 * Network connectivity tracker for Android.
 */
export class NetworkTracker {
  private currentType: NetworkType = "NONE";
  private events: NetworkChangeEvent[] = [];

  /** Called when the system reports a network change. */
  onNetworkChange(newType: NetworkType, now: number = Date.now()): void {
    if (this.currentType === newType) return;
    this.events.push({ oldType: this.currentType, newType, timestamp: now });
    if (this.events.length > 100) this.events.shift();
    this.currentType = newType;
  }

  getCurrentType(): NetworkType {
    return this.currentType;
  }

  /** True if the device has no direct Internet (only ShareNet). */
  isShareNetOnly(): boolean {
    return this.currentType === "SHARENET_ONLY" || this.currentType === "NONE";
  }

  /** True if mobile data is OFF and Wi-Fi is OFF (north-star condition). */
  isNorthStarCondition(): boolean {
    return this.currentType === "NONE";
  }

  getEvents(): readonly NetworkChangeEvent[] {
    return this.events;
  }
}

// -----------------------------------------------------------------------
// Battery/background handling
// -----------------------------------------------------------------------

/**
 * Android battery state for background operation.
 *
 * Per GATE-10: "battery/background handling." The ShareNet VPN service
 * runs as a foreground service (with a persistent notification) while
 * active. When the battery is low or the system is in Doze mode, the
 * adapter should reduce activity (lower keepalive frequency, reduce
 * background relay polling) but NOT drop the VPN tunnel.
 */
export type BatteryState = "CHARGING" | "NORMAL" | "LOW" | "CRITICAL" | "DOZE";

export interface BatteryEvent {
  oldState: BatteryState;
  newState: BatteryState;
  batteryPct: number;
  timestamp: number;
}

/**
 * Battery manager for Android VPN background behavior.
 */
export class BatteryManager {
  private state: BatteryState = "NORMAL";
  private batteryPct = 100;
  private events: BatteryEvent[] = [];

  /** Called when the battery level changes. */
  onBatteryChange(pct: number, now: number = Date.now()): void {
    const oldState = this.state;
    let newState: BatteryState;
    if (pct >= 80) newState = "NORMAL";
    else if (pct >= 30) newState = "NORMAL";
    else if (pct >= 15) newState = "LOW";
    else newState = "CRITICAL";

    if (pct >= 95 && this.isCharging()) newState = "CHARGING";

    this.batteryPct = pct;
    if (oldState !== newState) {
      this.events.push({ oldState, newState, batteryPct: pct, timestamp: now });
      if (this.events.length > 100) this.events.shift();
      this.state = newState;
    }
  }

  /** Called when the device enters/exits Doze mode. */
  onDozeMode(enabled: boolean, now: number = Date.now()): void {
    const oldState = this.state;
    const newState: BatteryState = enabled ? "DOZE" : (this.batteryPct >= 30 ? "NORMAL" : "LOW");
    if (oldState !== newState) {
      this.events.push({ oldState, newState, batteryPct: this.batteryPct, timestamp: now });
      this.state = newState;
    }
  }

  private isCharging(): boolean {
    return this.state === "CHARGING";
  }

  getState(): BatteryState {
    return this.state;
  }

  getBatteryPct(): number {
    return this.batteryPct;
  }

  /**
   * Get the recommended keepalive interval (ms) based on battery state.
   *
   * In normal operation: 30s keepalive.
   * In low battery: 60s (reduce frequency).
   * In critical/doze: 120s (minimal keepalive to preserve battery).
   */
  getKeepaliveIntervalMs(): number {
    switch (this.state) {
      case "CHARGING":
      case "NORMAL":
        return 30_000;
      case "LOW":
        return 60_000;
      case "CRITICAL":
      case "DOZE":
        return 120_000;
    }
  }

  getEvents(): readonly BatteryEvent[] {
    return this.events;
  }
}

// -----------------------------------------------------------------------
// Android VPN lifecycle (extends GATE-09 ProcessLifecycle)
// -----------------------------------------------------------------------

/**
 * Android VPN service lifecycle.
 *
 * Extends the platform-agnostic ProcessLifecycle with Android-specific
 * concerns: VPN permission, network changes, battery state.
 *
 * Transitions:
 *   STOPPED → (permission granted) → STARTING → RUNNING
 *   RUNNING → (permission revoked) → STOPPED (immediate — VPN killed by system)
 *   RUNNING → (network lost) → RECONNECTING → RUNNING (network restored)
 *   RUNNING → (network lost + battery critical) → STOPPED (preserve battery)
 */
export class AndroidVpnLifecycle {
  private lifecycle: ProcessLifecycle;
  private permissions: VpnPermissionManager;
  private network: NetworkTracker;
  private battery: BatteryManager;
  private reconnectAttempts = 0;
  private readonly maxReconnectAttempts = 5;

  constructor() {
    this.lifecycle = new ProcessLifecycle();
    this.permissions = new VpnPermissionManager();
    this.network = new NetworkTracker();
    this.battery = new BatteryManager();
  }

  /**
   * Attempt to start the VPN. Returns false if permission is not granted.
   */
  start(now: number = Date.now()): boolean {
    if (!this.permissions.canStartVpn()) {
      return false; // need permission first
    }
    this.reconnectAttempts = 0;
    return this.lifecycle.transition("STARTING", "VPN start requested", now);
  }

  /** Called when the TUN device is up and the circuit is established. */
  onTunUp(now: number = Date.now()): void {
    this.lifecycle.transition("RUNNING", "TUN up, circuit established", now);
  }

  /** Called when the network changes. May trigger reconnect. */
  onNetworkChange(newType: NetworkType, now: number = Date.now()): void {
    const oldType = this.network.getCurrentType();
    this.network.onNetworkChange(newType, now);

    if (this.lifecycle.getState() !== "RUNNING") return;

    if (newType === "NONE" || newType === "SHARENET_ONLY") {
      // Network lost — try to reconnect (if not in critical battery)
      if (this.battery.getState() === "CRITICAL") {
        this.lifecycle.transition("STOPPING", "network lost + critical battery — stop to preserve battery", now);
        this.lifecycle.transition("STOPPED", "graceful stop (battery)", now);
      } else if (this.reconnectAttempts < this.maxReconnectAttempts) {
        this.reconnectAttempts++;
        this.lifecycle.transition("DEGRADED", `network changed (${oldType}→${newType}), reconnect attempt ${this.reconnectAttempts}`, now);
      }
    }
  }

  /** Called when VPN permission is revoked by the system. */
  onPermissionRevoked(now: number = Date.now()): void {
    this.permissions.revokePermission(now);
    // VPN is immediately killed by the system
    if (this.lifecycle.getState() === "RUNNING" || this.lifecycle.getState() === "DEGRADED") {
      this.lifecycle.transition("CRASHED", "VPN permission revoked — system killed the tunnel", now);
    }
  }

  /** Called when battery state changes. */
  onBatteryChange(pct: number, now: number = Date.now()): void {
    this.battery.onBatteryChange(pct, now);
  }

  /** Called when Doze mode is entered/exited. */
  onDozeMode(enabled: boolean, now: number = Date.now()): void {
    this.battery.onDozeMode(enabled, now);
  }

  /** Stop the VPN. */
  stop(now: number = Date.now()): void {
    this.lifecycle.transition("STOPPING", "user requested stop", now);
    this.lifecycle.transition("STOPPED", "VPN stopped", now);
  }

  // --- accessors ---

  getState(): ProcessState {
    return this.lifecycle.getState();
  }

  getPermissions(): VpnPermissionManager {
    return this.permissions;
  }

  getNetwork(): NetworkTracker {
    return this.network;
  }

  getBattery(): BatteryManager {
    return this.battery;
  }

  getKillSwitch(): KillSwitch {
    return this.lifecycle.getKillSwitch();
  }

  getReconnectAttempts(): number {
    return this.reconnectAttempts;
  }
}

// -----------------------------------------------------------------------
// Reproducible device test script
// -----------------------------------------------------------------------

/**
 * The north-star test script (reproducible).
 *
 * This defines the exact steps for the Android north-star test.
 * A real implementation would execute these via ADB (Android Debug Bridge)
 * commands. The script is defined as data so it can be versioned and
 * reproduced exactly.
 */
export interface TestStep {
  step: number;
  description: string;
  command: string; // ADB command or manual action
  expected: string;
  isManual: boolean;
}

export const NORTH_STAR_TEST_SCRIPT: readonly TestStep[] = [
  {
    step: 1,
    description: "Ensure Android device is connected via ADB",
    command: "adb devices",
    expected: "Device listed with 'device' status",
    isManual: false,
  },
  {
    step: 2,
    description: "Turn OFF mobile data",
    command: "adb shell svc data disable",
    expected: "Mobile data OFF",
    isManual: false,
  },
  {
    step: 3,
    description: "Turn OFF Wi-Fi",
    command: "adb shell svc wifi disable",
    expected: "Wi-Fi OFF — no direct Internet connectivity",
    isManual: false,
  },
  {
    step: 4,
    description: "Verify no direct Internet (Chrome cannot reach HTTPS)",
    command: "adb shell am start -a android.intent.action.VIEW -d https://example.com",
    expected: "Chrome shows 'No internet' or ERR_INTERNET_DISCONNECTED",
    isManual: true,
  },
  {
    step: 5,
    description: "Start ShareNet VPN service",
    command: "adb shell am start -n dev.sharenet.app/.VpnControlActivity --ez start true",
    expected: "ShareNet VPN permission dialog (first time) → GRANT → VPN active (notification appears)",
    isManual: true,
  },
  {
    step: 6,
    description: "Wait for ShareNet to establish circuit (relay → gateway)",
    command: "adb shell logcat -d | grep ShareNet | grep CIRCUIT_ESTABLISHED",
    expected: "Log entry: 'CIRCUIT_ESTABLISHED route_id=... gateway=...'",
    isManual: false,
  },
  {
    step: 7,
    description: "Open Chrome and navigate to https://example.com",
    command: "adb shell am start -a android.intent.action.VIEW -d https://example.com",
    expected: "Chrome loads example.com successfully (through ShareNet → relay → gateway → real Internet)",
    isManual: true,
  },
  {
    step: 8,
    description: "Verify traffic went through ShareNet (check gateway audit log)",
    command: "adb shell logcat -d | grep ShareNet | grep GATEWAY_REQUEST_ALLOWED",
    expected: "Log entry: 'GATEWAY_REQUEST_ALLOWED destination=example.com:443'",
    isManual: false,
  },
  {
    step: 9,
    description: "Verify mobile data and Wi-Fi are still OFF",
    command: "adb shell settings get global mobile_data && adb shell svc wifi status",
    expected: "mobile_data=0, wifi=disabled",
    isManual: false,
  },
  {
    step: 10,
    description: "Repeat steps 7-9 three times for reproducibility",
    command: "(repeat 3 times)",
    expected: "All 3 runs succeed: Chrome reaches real HTTPS through ShareNet with no direct Internet",
    isManual: true,
  },
] as const;

/**
 * The expected test result for the north-star test.
 */
export interface NorthStarTestResult {
  mobileDataOff: boolean;
  wifiOff: boolean;
  chromeReachedHttps: boolean;
  trafficViaShareNet: boolean;
  repeatedRuns: number;
  allRunsSucceeded: boolean;
  timestamp: number;
}
