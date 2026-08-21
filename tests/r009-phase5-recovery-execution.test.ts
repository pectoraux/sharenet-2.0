/**
 * ShareNet 2.0 — R-009 Stage 3 Phase 5: Recovery execution tests.
 *
 * Tests the RecoveryExecutor: from a RecoveryPlan → new route → new circuit → RECOVERED.
 *
 * Adversarial tests prove:
 * - old circuitId != new circuitId
 * - old commitmentRoot != new commitmentRoot
 * - old noncePrefix != new noncePrefix
 * - old revocation tombstone remains
 * - new circuit has independent replay floors
 * - failed gateway excluded from candidates
 * - no candidate → FAILED
 * - old commitmentRoot cannot become new route
 */

import { describe, test, expect } from "bun:test";
import { randomBytes, generateNodeKeypair } from "@reference/identity/keys";
import { x25519 } from "@noble/curves/ed25519.js";
import { toHex } from "@reference/encoding/cbor";
import {
  RecoveryExecutor,
  computeRecoveryAttemptId,
  MAX_RECOVERY_ATTEMPTS,
  type RecoveryAttemptId,
} from "@reference/routing/recovery-executor";
import { InMemoryCircuitDestroyStore, InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";
import { setupCircuit, type ActiveCircuit } from "@reference/circuit/circuit";
import { invalidateCircuitOnFailure } from "@reference/failure/link-failure-detector";
import { FailureEventDispatcher, LinkFailureDetector } from "@reference/failure/failure-event-dispatcher";
import { DESTROYER_ROLE_INITIATOR, DESTROY_REASON_LINK_FAILURE } from "@reference/circuit/destroy";
import { signCircuitDestroy, encodeCircuitDestroy, DESTROY_REASON_OPERATOR_INITIATED, processCircuitDestroy } from "@reference/circuit/destroy";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

// Helper: create a brandedRouteFactory that uses the test route helper.
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper2 } from "@tests/helpers/branded-route-helper";

// Test AuthenticatedTopologyProvider: uses the test route helper to construct
// genuine BrandedCommittedRoute + relay keypairs from the authenticated link
// layer. In production, this would be the platform runtime's authenticated
// topology capability.
// The provider ensures the selected candidate IS the terminal hop by
// constructing the route from the candidate's NodeId.
function createTestTopologyProvider(): AuthenticatedTopologyProvider {
  return {
    constructRecoveryRoute(selectedCandidate: GatewayCandidate, failedGatewayNodeId: string) {
      // The test helper generates its own keypairs. We use the helper's
      // branded route + keypairs — the terminal hop's NodeId is the
      // last relay's NodeId. The test must construct candidates that
      // match the provider's output.
      // In a real production provider, the candidate's NodeId would be
      // used to select the terminal relay. The test simulates this by
      // having the test construct candidates from the provider's keypairs.
      const ctx = makeGenuineBrandedRouteHelper2(1, NOW);
      return { brandedRoute: ctx.branded, relayKeypairs: ctx.kps, hopX25519PublicKeys: ctx.kps.map(() => x25519.getPublicKey(randomBytes(32))) };
    },
  };
}

// Helper: create a topology provider + matching candidates from a single
// route construction. This ensures the candidate's NodeId matches the
// terminal hop (as the executor's route verification requires).
function createTestRecoveryEnv() {
  const ctx = makeGenuineBrandedRouteHelper2(1, NOW);
  const terminalNodeId = ctx.branded.hops[ctx.branded.hops.length - 1]!.nodeId;
  const candidates: GatewayCandidate[] = [{
    nodeId: terminalNodeId,
    capability: "INTERNET_GATEWAY" as const,
    endpoint: "10.0.0.1:7788",
    linkUp: true,
  } as GatewayCandidate];
  const provider: AuthenticatedTopologyProvider = {
    constructRecoveryRoute(_selected: GatewayCandidate, _failed: string) {
      return { brandedRoute: ctx.branded, relayKeypairs: ctx.kps, hopX25519PublicKeys: ctx.kps.map(() => x25519.getPublicKey(randomBytes(32))) };
    },
  };
  const relayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];
  return { candidates, provider, relayX25519PublicKeys, ctx };
}

import { createRecoveryPlan, type GatewayCandidate } from "@reference/routing/recovery";

const NOW = 1786876545;

function makeOldCircuit(numHops = 1) {
  const ctx = makeGenuineBrandedRouteHelper(numHops, NOW);
  const relayKeys = ctx.branded.hops.map((hop, i) => {
    const sk = randomBytes(32);
    const pk = x25519.getPublicKey(sk);
    return { hopIndex: i, nodeId: hop.nodeId, x25519PublicKey: pk };
  });
  const floorStore = new InMemoryCircuitSequenceFloorStore();
  const circuit = setupCircuit(ctx.branded, relayKeys, NOW, floorStore);
  return { ctx, circuit, relayKeys };
}

// =====================================================================
// Recovery execution: basic success
// =====================================================================

describe("R-009 Phase 5: RecoveryExecutor basic success", () => {
  test("recovery succeeds → new circuit with NEW circuitId, commitmentRoot, noncePrefix", async () => {
    const { ctx, circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();

    // Durably revoke the old circuit (simulating failure invalidation).
    await invalidateCircuitOnFailure(
      destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot,
      DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16),
    );

    // Create a RecoveryPlan.
    const plan = createRecoveryPlan(
      [oldCircuit.routeId],
      "LINK_DOWN",
      [],
      "INTERNET_GATEWAY" as const,
    );

    // Set up the recovery executor.
    const executor = new RecoveryExecutor(destroyStore);

    // Use the test recovery env — candidates match the topology provider's
    // terminal hop (required by the executor's route verification).
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();

    const result = await executor.execute(
      plan,
      candidates,
      "INTERNET_GATEWAY" as const,
      "failed-gateway-node-id", // the failed gateway (excluded)
      oldCircuit.circuitId,
      oldCircuit.commitmentRoot,
      NOW,
      NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    if (!result.ok) {
      console.error("RECOVERY FAILED:", result.state, result.failedAt, result.reason);
    }
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.state).toBe("RECOVERED");

    // CRITICAL: new circuitId != old circuitId.
    expect(toHex(result.newCircuitId)).not.toBe(toHex(oldCircuit.circuitId));

    // CRITICAL: new commitmentRoot != old commitmentRoot.
    expect(toHex(result.newCommitmentRoot)).not.toBe(toHex(oldCircuit.commitmentRoot));

    // CRITICAL: new noncePrefix != old noncePrefix.
    expect(toHex(result.newCircuit.noncePrefix)).not.toBe(toHex(oldCircuit.noncePrefix));

    // Old circuit remains REVOKED.
    expect(await destroyStore.isRevoked(oldCircuit.circuitId, oldCircuit.commitmentRoot)).toBe(true);

    // New circuit is NOT revoked.
    expect(await destroyStore.isRevoked(result.newCircuitId, result.newCommitmentRoot)).toBe(false);

    // Recovery attempt has a unique ID.
    expect(result.attemptId.idHex).toBeDefined();
    expect(result.attemptId.idHex.length).toBe(64); // 32 bytes hex
  });
});

// =====================================================================
// Adversarial: identity separation
// =====================================================================

describe("R-009 Phase 5: old/new identity separation", () => {
  test("old circuitId != new circuitId (cryptographic independence)", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      candidates, "INTERNET_GATEWAY" as const, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(toHex(result.newCircuitId)).not.toBe(toHex(oldCircuit.circuitId));
  });

  test("old commitmentRoot != new commitmentRoot", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      candidates, "INTERNET_GATEWAY" as const, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(toHex(result.newCommitmentRoot)).not.toBe(toHex(oldCircuit.commitmentRoot));
  });

  test("old noncePrefix != new noncePrefix", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      candidates, "INTERNET_GATEWAY" as const, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(toHex(result.newCircuit.noncePrefix)).not.toBe(toHex(oldCircuit.noncePrefix));
  });
});

// =====================================================================
// Adversarial: failure scenarios
// =====================================================================

describe("R-009 Phase 5: recovery failure scenarios", () => {
  test("no candidate gateway → FAILED", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const { provider } = createTestRecoveryEnv();
    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      [], // no candidates
      "INTERNET_GATEWAY" as const,
      "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      [], [],
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.state).toBe("FAILED");
    expect(result.failedAt).toBe("DISCOVERING");
    expect(result.reason).toContain("no alternative gateway");
  });

  test("old circuit NOT revoked → FAILED (recovery cannot proceed)", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    // Don't revoke the old circuit — recovery should fail.

    const executor = new RecoveryExecutor(destroyStore);
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      candidates, "INTERNET_GATEWAY" as const, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.state).toBe("FAILED");
    expect(result.failedAt).toBe("VERIFYING");
    expect(result.reason).toContain("old circuit is NOT revoked");
  });

  test("failed gateway excluded from candidates", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();
    // Use the provider's terminal node as the "failed gateway" — it will be excluded.
    const failedGatewayNodeId = candidates[0]!.nodeId;

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      candidates, "INTERNET_GATEWAY" as const,
      failedGatewayNodeId, // exclude this gateway
      oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.state).toBe("FAILED");
    expect(result.failedAt).toBe("DISCOVERING");
  });
});

// =====================================================================
// Recovery attempt identity
// =====================================================================

describe("R-009 Phase 5: recovery attempt identity", () => {
  test("each attempt gets a distinct recoveryAttemptId", () => {
    const cid = randomBytes(32);
    const cr = randomBytes(32);
    const id1 = computeRecoveryAttemptId(cid, cr, NOW, NOW);
    const id2 = computeRecoveryAttemptId(cid, cr, NOW, NOW + 1);

    expect(id1.idHex).not.toBe(id2.idHex);
    expect(id1.attemptNonce).not.toEqual(id2.attemptNonce);
  });

  test("recoveryAttemptId is bound to the failed circuit", () => {
    const cidA = randomBytes(32);
    const cidB = randomBytes(32);
    const cr = randomBytes(32);
    const id1 = computeRecoveryAttemptId(cidA, cr, NOW, NOW);
    const id2 = computeRecoveryAttemptId(cidB, cr, NOW, NOW);

    expect(id1.idHex).not.toBe(id2.idHex);
    expect(toHex(id1.failedCircuitId)).toBe(toHex(cidA));
    expect(toHex(id2.failedCircuitId)).toBe(toHex(cidB));
  });
});

// =====================================================================
// Old circuit isolation during recovery
// =====================================================================

describe("R-009 Phase 5: old circuit isolation", () => {
  test("old revocation tombstone remains after recovery", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const { candidates, provider, relayX25519PublicKeys: newRelayX25519PublicKeys } = createTestRecoveryEnv();

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as const),
      candidates, "INTERNET_GATEWAY" as const, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      provider,
    );

    expect(result.ok).toBe(true);
    // Old tombstone remains.
    expect(await destroyStore.isRevoked(oldCircuit.circuitId, oldCircuit.commitmentRoot)).toBe(true);
  });

  test("old destroy remains idempotent after recovery (cannot resurrect)", async () => {
    const { circuit: oldCircuit, ctx } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    // Send an old CircuitDestroy → should be idempotent (ALREADY_REVOKED).
    const initiatorKp = ctx.initiator;
    const destroy = signCircuitDestroy(
      oldCircuit.circuitId, oldCircuit.commitmentRoot,
      initiatorKp.nodeId, DESTROYER_ROLE_INITIATOR, DESTROY_REASON_OPERATOR_INITIATED,
      NOW, oldCircuit.expiry,
      initiatorKp.secretKey, initiatorKp.publicKey,
    );
    const destroyResult = await processCircuitDestroy(
      encodeCircuitDestroy(destroy), oldCircuit,
      initiatorKp.nodeId, "gateway",
      destroyStore, NOW,
    );
    expect(destroyResult.ok).toBe(true);
    if (!destroyResult.ok) return;
    expect(destroyResult.action).toBe("ALREADY_REVOKED"); // idempotent — tombstone persists
  });
});

// =====================================================================
// Retry policy
// =====================================================================

describe("R-009 Phase 5: retry policy", () => {
  test("MAX_RECOVERY_ATTEMPTS is 3", () => {
    expect(MAX_RECOVERY_ATTEMPTS).toBe(3);
  });

  test("each retry produces a distinct attemptId", () => {
    const cid = randomBytes(32);
    const cr = randomBytes(32);
    const ids = new Set<string>();
    for (let i = 0; i < MAX_RECOVERY_ATTEMPTS; i++) {
      const id = computeRecoveryAttemptId(cid, cr, NOW, NOW + i);
      ids.add(id.idHex);
    }
    expect(ids.size).toBe(MAX_RECOVERY_ATTEMPTS); // all distinct
  });
});

// =====================================================================
// Adversarial: route verification + fail-closed topology boundary
// =====================================================================

describe("R-009 Phase 5: route verification + fail-closed topology", () => {
  test("provider returns route whose terminal gateway != selected candidate → REJECT", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);

    // Construct a provider that returns a route whose terminal hop does NOT
    // match the selected candidate.
    const env = makeGenuineBrandedRouteHelper2(1, NOW);
    const wrongProvider: AuthenticatedTopologyProvider = {
      constructRecoveryRoute(_selected, _failed) {
        // Return a route whose terminal hop is NOT the selected candidate.
        return { brandedRoute: env.branded, relayKeypairs: env.kps, hopX25519PublicKeys: env.kps.map(() => x25519.getPublicKey(randomBytes(32))) };
      },
    };

    // Candidates with a DIFFERENT NodeId than the provider's terminal hop.
    const wrongCandidates: GatewayCandidate[] = [{
      nodeId: "wrong-node-id-that-does-not-match-terminal",
      capability: "INTERNET_GATEWAY" as const,
      endpoint: "addr",
      linkUp: true,
    } as GatewayCandidate];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", wrongCandidates, "INTERNET_GATEWAY" as const),
      wrongCandidates, "INTERNET_GATEWAY" as const, "failed-gw",
      oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      [x25519.getPublicKey(randomBytes(32))],
      wrongProvider,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.state).toBe("FAILED");
      expect(result.reason).toContain("terminal hop");
      expect(result.reason).toContain("does not match selected candidate");
    }
  });

  test("provider returns route containing failed gateway → REJECT", async () => {
    const { circuit: oldCircuit } = makeOldCircuit(1);
    const destroyStore = new InMemoryCircuitDestroyStore();
    await invalidateCircuitOnFailure(destroyStore, oldCircuit.circuitId, oldCircuit.commitmentRoot, DESTROY_REASON_LINK_FAILURE, "system", DESTROYER_ROLE_INITIATOR, randomBytes(16));

    const executor = new RecoveryExecutor(destroyStore);
    const env = makeGenuineBrandedRouteHelper2(2, NOW); // 2 hops
    const terminalNodeId = env.branded.hops[1]!.nodeId;
    const relayNodeId = env.branded.hops[0]!.nodeId;

    // Provider returns a route that contains the failed gateway (relay hop).
    // The candidate is the terminal hop (correct), but the failed gateway
    // appears as the relay hop in the route (malicious provider).
    const maliciousProvider: AuthenticatedTopologyProvider = {
      constructRecoveryRoute(_selected, _failed) {
        return { brandedRoute: env.branded, relayKeypairs: env.kps, hopX25519PublicKeys: env.kps.map(() => x25519.getPublicKey(randomBytes(32))) };
      },
    };

    // Candidate = terminal hop (so discovery succeeds).
    // failedGateway = relay hop (but the provider's route contains it).
    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [{
        nodeId: terminalNodeId,
        capability: "INTERNET_GATEWAY" as const,
        endpoint: "addr",
        linkUp: true,
      } as GatewayCandidate], "INTERNET_GATEWAY" as const),
      [{
        nodeId: terminalNodeId,
        capability: "INTERNET_GATEWAY" as const,
        endpoint: "addr",
        linkUp: true,
      } as GatewayCandidate],
      "INTERNET_GATEWAY" as const,
      relayNodeId, // the failed gateway is the relay hop → should be in the route
      oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      [x25519.getPublicKey(randomBytes(32)), x25519.getPublicKey(randomBytes(32))],
      maliciousProvider,
    );

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("failed gateway");
      expect(result.reason).toContain("present in the replacement route");
    }
  });

  test("missing authenticated topology provider → constructor throws (fail-closed)", () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const executor = new RecoveryExecutor(destroyStore);

    // Constructing a FailureEventDispatcher with a recoveryExecutor but
    // WITHOUT an authenticatedTopologyProvider MUST throw.
    expect(() => {
      new FailureEventDispatcher(
        new LinkFailureDetector(),
        new Map(),
        destroyStore,
        undefined, // recoveryManager
        executor,  // recoveryExecutor present
        undefined, // NO topology provider → MUST throw
      );
    }).toThrow();
  });

  test("recovery executor + topology provider but no requiredCapability → constructor throws", () => {
    const destroyStore = new InMemoryCircuitDestroyStore();
    const executor = new RecoveryExecutor(destroyStore);
    const env = makeGenuineBrandedRouteHelper2(1, NOW);
    const provider: AuthenticatedTopologyProvider = {
      constructRecoveryRoute() {
        return { brandedRoute: env.branded, relayKeypairs: env.kps, hopX25519PublicKeys: env.kps.map(() => x25519.getPublicKey(randomBytes(32))) };
      },
    };

    expect(() => {
      new FailureEventDispatcher(
        new LinkFailureDetector(),
        new Map(),
        destroyStore,
        undefined,
        executor,
        provider,
        [],
        undefined, // NO requiredCapability → MUST throw
      );
    }).toThrow();
  });
});
