/**
 * ShareNet 2.0 — Linux TUN Adapter Abstraction (GATE-09).
 *
 * Per spec/16-platforms.md and GATE-09 requirements:
 *
 *   - Linux TUN adapter
 *   - local proxy/TUN policy
 *   - DNS leak prevention
 *   - process lifecycle and kill-switch behavior
 *   - browser integration test (deferred — requires full real-process stack)
 *
 * This module defines the platform-agnostic TUN adapter interface and
 * the Linux-specific policy. The protocol core (reference/) defines the
 * abstraction; the platform adapter (platform/linux/) implements it with
 * real TUN device calls.
 *
 * Per spec/16 §1: "Platform adapters must NOT create platform-specific
 * protocol semantics. The protocol core is platform-agnostic."
 */

// -----------------------------------------------------------------------
// TUN adapter interface (platform-agnostic)
// -----------------------------------------------------------------------

/**
 * A TUN adapter captures outgoing IP packets from the host's network stack
 * and redirects them through ShareNet circuits. It is the user-space
 * equivalent of a VPN tunnel.
 *
 * Platform implementations:
 *   - Linux: /dev/net/tun (TUN/TAP device)
 *   - Windows: Wintap / Wintun
 *   - macOS: Network Extension (utun)
 *   - Android: VPNService
 *   - iOS: Network Extension (NEPacketTunnelProvider)
 *
 * Per spec/16 §1: all platforms use the SAME protocol core. The TUN adapter
 * is a platform-specific transport, NOT a protocol modification.
 */
export interface TunAdapter {
  /** Start the TUN device and begin capturing packets. */
  start(): Promise<void>;

  /** Stop the TUN device and release all resources. */
  stop(): Promise<void>;

  /** True if the TUN device is currently active. */
  isActive(): boolean;

  /** Get the TUN device's virtual IP address (e.g. "10.8.0.1"). */
  getTunAddress(): string;

  /** Get the MTU of the TUN device. */
  getMtu(): number;
}

// -----------------------------------------------------------------------
// TUN policy (what traffic the adapter routes through ShareNet)
// -----------------------------------------------------------------------

/**
 * TUN routing policy — determines which traffic goes through ShareNet
 * vs. directly to the Internet.
 *
 * Per GATE-09: "no direct Internet route is used by the test client."
 * The kill-switch ensures that if the TUN adapter goes down, all
 * traffic is blocked (no leak to the direct Internet route).
 */
export interface TunPolicy {
  /** CIDR ranges to route through ShareNet (e.g. "0.0.0.0/0" for all). */
  routeRanges: readonly string[];
  /** DNS servers to use (ShareNet DNS proxy, not system DNS). */
  dnsServers: readonly string[];
  /** Whether to block all non-ShareNet traffic when TUN is active (kill-switch). */
  killSwitch: boolean;
  /** Domains to bypass ShareNet (split tunneling). Empty = no bypass. */
  bypassDomains: readonly string[];
  /** Whether to block IPv6 (prevent IPv6 DNS leaks). */
  blockIpv6: boolean;
}

export function defaultTunPolicy(): TunPolicy {
  return {
    routeRanges: ["0.0.0.0/0"], // route ALL traffic through ShareNet
    dnsServers: ["10.8.0.53"], // ShareNet DNS proxy (virtual)
    killSwitch: true,
    bypassDomains: [],
    blockIpv6: true, // block IPv6 to prevent DNS leaks via IPv6
  };
}

// -----------------------------------------------------------------------
// DNS leak prevention
// -----------------------------------------------------------------------

/**
 * Check if a DNS query would leak (go to the system DNS instead of ShareNet).
 *
 * Per GATE-09: "DNS leak prevention." All DNS queries MUST go through the
 * ShareNet DNS proxy, not the system resolver. IPv6 DNS queries are blocked
 * entirely if blockIpv6 is true.
 */
export function wouldDnsLeak(
  dnsServer: string,
  queryType: "A" | "AAAA" | "MX" | "TXT" | "CNAME" | "PTR",
  policy: TunPolicy,
): { ok: true } | { ok: false; reason: string } {
  // Check if the DNS server is in the allowed list
  if (!policy.dnsServers.includes(dnsServer)) {
    return {
      ok: false,
      reason: `DNS server ${dnsServer} not in ShareNet DNS list — would leak to system resolver`,
    };
  }

  // Block IPv6 queries if configured (prevent AAAA leak)
  if (policy.blockIpv6 && queryType === "AAAA") {
    return {
      ok: false,
      reason: "AAAA query blocked (IPv6 DNS leak prevention) — blockIpv6=true",
    };
  }

  return { ok: true };
}

/**
 * Check if a destination would bypass ShareNet (split tunneling).
 *
 * Per GATE-09: "local proxy/TUN policy." If the destination matches a
 * bypass domain, traffic goes directly (NOT through ShareNet).
 * The kill-switch prevents even bypass traffic when the TUN is down.
 */
export function wouldBypassShareNet(
  destination: string,
  policy: TunPolicy,
): { bypass: boolean; reason: string } {
  const host = destination.split(":")[0]?.toLowerCase() ?? destination.toLowerCase();

  // Check bypass domains
  for (const pattern of policy.bypassDomains) {
    if (pattern === "*" || pattern === host || (pattern.startsWith("*.") && (host === pattern.slice(2) || host.endsWith("." + pattern.slice(2))))) {
      return { bypass: true, reason: `host ${host} matches bypass pattern ${pattern}` };
    }
  }

  return { bypass: false, reason: `host ${host} routed through ShareNet` };
}

// -----------------------------------------------------------------------
// Kill-switch
// -----------------------------------------------------------------------

/**
 * Kill-switch state — when the TUN adapter goes down unexpectedly,
 * all traffic is blocked to prevent leaks to the direct Internet.
 *
 * Per GATE-09: "process lifecycle and kill-switch behavior."
 *
 * The kill-switch is a safety mechanism: if the TUN device fails or the
 * ShareNet process crashes, the host's network configuration is modified
 * to block all outgoing traffic until the TUN is restored or the user
 * explicitly disables the kill-switch.
 */
export class KillSwitch {
  private active = false;
  private tunActive = false;
  private blocked = false;

  /** Called when the TUN adapter starts. Disables the block. */
  onTunStart(): void {
    this.tunActive = true;
    this.blocked = false;
  }

  /** Called when the TUN adapter stops (graceful). Does NOT trigger block. */
  onTunStop(): void {
    this.tunActive = false;
    if (this.active) {
      // Kill-switch is enabled — block traffic
      this.blocked = true;
    }
  }

  /** Called when the TUN adapter fails unexpectedly. Triggers block. */
  onTunFailure(): void {
    this.tunActive = false;
    if (this.active) {
      this.blocked = true;
    }
  }

  /** Enable the kill-switch. */
  enable(): void {
    this.active = true;
    if (!this.tunActive) {
      this.blocked = true;
    }
  }

  /** Disable the kill-switch (user explicitly allows direct traffic). */
  disable(): void {
    this.active = false;
    this.blocked = false;
  }

  /** True if traffic is currently blocked (kill-switch active + TUN down). */
  isBlocked(): boolean {
    return this.blocked;
  }

  /** True if the kill-switch is enabled. */
  isEnabled(): boolean {
    return this.active;
  }

  /** True if the TUN adapter is currently active. */
  isTunActive(): boolean {
    return this.tunActive;
  }
}

// -----------------------------------------------------------------------
// Process lifecycle
// -----------------------------------------------------------------------

export type ProcessState = "STOPPED" | "STARTING" | "RUNNING" | "DEGRADED" | "STOPPING" | "CRASHED";

export interface ProcessLifecycleEvent {
  oldState: ProcessState;
  newState: ProcessState;
  timestamp: number;
  reason: string;
}

/**
 * Process lifecycle manager for the ShareNet TUN client.
 *
 * Per GATE-09: "process lifecycle and kill-switch behavior."
 *
 * States:
 *   STOPPED  → STARTING → RUNNING → DEGRADED → RUNNING (recovery)
 *                       → STOPPING → STOPPED (graceful)
 *                       → CRASHED  → STARTING (restart)
 */
export class ProcessLifecycle {
  private state: ProcessState = "STOPPED";
  private events: ProcessLifecycleEvent[] = [];
  private killSwitch: KillSwitch;
  private restartCount = 0;
  private maxRestarts = 3;

  constructor(killSwitch?: KillSwitch) {
    this.killSwitch = killSwitch ?? new KillSwitch();
  }

  /** Transition to a new state. Returns false if the transition is invalid. */
  transition(newState: ProcessState, reason: string, now: number = Date.now()): boolean {
    const valid: Record<ProcessState, ProcessState[]> = {
      STOPPED: ["STARTING"],
      STARTING: ["RUNNING", "CRASHED", "STOPPED"],
      RUNNING: ["DEGRADED", "STOPPING", "CRASHED"],
      DEGRADED: ["RUNNING", "STOPPING", "CRASHED"],
      STOPPING: ["STOPPED", "CRASHED"],
      CRASHED: ["STARTING", "STOPPED"],
    };

    if (!valid[this.state].includes(newState)) {
      return false; // invalid transition
    }

    const event: ProcessLifecycleEvent = {
      oldState: this.state,
      newState,
      timestamp: now,
      reason,
    };
    this.events.push(event);
    if (this.events.length > 100) this.events.shift();

    this.state = newState;

    // Kill-switch integration
    if (newState === "RUNNING") {
      this.killSwitch.onTunStart();
    } else if (newState === "STOPPED") {
      this.killSwitch.onTunStop();
    } else if (newState === "CRASHED" || newState === "DEGRADED") {
      this.killSwitch.onTunFailure();
    }

    // Auto-restart on crash
    if (newState === "CRASHED" && this.restartCount < this.maxRestarts) {
      this.restartCount++;
      this.transition("STARTING", `auto-restart ${this.restartCount}/${this.maxRestarts}`, now);
    }

    return true;
  }

  getState(): ProcessState {
    return this.state;
  }

  getEvents(): readonly ProcessLifecycleEvent[] {
    return this.events;
  }

  getKillSwitch(): KillSwitch {
    return this.killSwitch;
  }

  getRestartCount(): number {
    return this.restartCount;
  }

  resetRestartCount(): void {
    this.restartCount = 0;
  }
}

// -----------------------------------------------------------------------
// Linux-specific TUN configuration
// -----------------------------------------------------------------------

/**
 * Linux TUN device configuration.
 *
 * On Linux, the TUN device is created via /dev/net/tun with ioctl()
 * calls. The configuration specifies the virtual interface name, IP,
 * MTU, and routing rules.
 *
 * This type is the platform-specific config; the platform-agnostic
 * interface is TunAdapter.
 */
export interface LinuxTunConfig {
  /** Interface name (e.g. "sharenet0"). Max 15 chars. */
  interfaceName: string;
  /** Virtual IP address for the TUN interface. */
  address: string;
  /** Netmask (e.g. "255.255.255.0"). */
  netmask: string;
  /** MTU (default 1400 to account for ShareNet overhead). */
  mtu: number;
  /** CIDR ranges to route through the TUN. */
  routeRanges: readonly string[];
  /** DNS server to configure (ShareNet DNS proxy). */
  dnsServer: string;
}

export function defaultLinuxTunConfig(): LinuxTunConfig {
  return {
    interfaceName: "sharenet0",
    address: "10.8.0.1",
    netmask: "255.255.255.0",
    mtu: 1400,
    routeRanges: ["0.0.0.0/0"],
    dnsServer: "10.8.0.53",
  };
}

/**
 * Architecture guard: platform adapters must NOT create protocol semantics.
 *
 * Per spec/16 §1: "Platform adapters must NOT create platform-specific
 * protocol semantics. The protocol core is platform-agnostic."
 */
export function PLATFORM_PROTOCOL_SEMANTICS_FORBIDDEN(platform: string, semantic: string): never {
  throw new Error(
    `ARCHITECTURE VIOLATION: platform adapter '${platform}' attempted to create ` +
      `protocol semantic '${semantic}'. Per spec/16 §1, platform adapters MUST NOT ` +
      `create platform-specific protocol semantics. The protocol core is ` +
      `platform-agnostic. Any new protocol behavior must go through the spec → ADR → ` +
      `reference implementation pipeline, not the platform adapter.`,
  );
}
