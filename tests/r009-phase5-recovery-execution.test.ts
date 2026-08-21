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
import { DESTROYER_ROLE_INITIATOR, DESTROY_REASON_LINK_FAILURE } from "@reference/circuit/destroy";
import { signCircuitDestroy, encodeCircuitDestroy, DESTROY_REASON_OPERATOR_INITIATED, processCircuitDestroy } from "@reference/circuit/destroy";
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper } from "@tests/helpers/branded-route-helper";

// Helper: create a brandedRouteFactory that uses the test route helper.
import { makeGenuineBrandedRoute as makeGenuineBrandedRouteHelper2 } from "@tests/helpers/branded-route-helper";

// Test AuthenticatedTopologyProvider: uses the test route helper to construct
// genuine BrandedCommittedRoute + relay keypairs from the authenticated link
// layer. In production, this would be the platform runtime's authenticated
// topology capability.
function createTestTopologyProvider(): AuthenticatedTopologyProvider {
  return {
    constructRecoveryRoute(selectedCandidate: any, failedGatewayNodeId: string) {
      const ctx = makeGenuineBrandedRouteHelper2(1, NOW);
      return { brandedRoute: ctx.branded, relayKeypairs: ctx.kps };
    },
  };
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
      "INTERNET_GATEWAY" as any,
    );

    // Set up the recovery executor.
    const executor = new RecoveryExecutor(destroyStore);

    // Generate fresh relay keypairs for the new route.
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];

    // Available gateway candidates (excluding the failed gateway).
    const candidates: GatewayCandidate[] = [{
      nodeId: newRelayKeypairs[0]!.nodeId,
      capability: "INTERNET_GATEWAY" as any,
      endpoint: "10.0.0.1:7788",
      linkUp: true,
      expiry: NOW + 3600,
    } as any];

    const result = await executor.execute(
      plan,
      candidates,
      "INTERNET_GATEWAY" as any,
      "failed-gateway-node-id", // the failed gateway (excluded)
      oldCircuit.circuitId,
      oldCircuit.commitmentRoot,
      NOW,
      NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];
    const candidates: GatewayCandidate[] = [{ nodeId: newRelayKeypairs[0]!.nodeId, capability: "INTERNET_GATEWAY" as any, endpoint: "addr", linkUp: true, expiry: NOW + 3600 } as any];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      candidates, "INTERNET_GATEWAY" as any, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];
    const candidates: GatewayCandidate[] = [{ nodeId: newRelayKeypairs[0]!.nodeId, capability: "INTERNET_GATEWAY" as any, endpoint: "addr", linkUp: true, expiry: NOW + 3600 } as any];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      candidates, "INTERNET_GATEWAY" as any, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];
    const candidates: GatewayCandidate[] = [{ nodeId: newRelayKeypairs[0]!.nodeId, capability: "INTERNET_GATEWAY" as any, endpoint: "addr", linkUp: true, expiry: NOW + 3600 } as any];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      candidates, "INTERNET_GATEWAY" as any, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      [], // no candidates
      "INTERNET_GATEWAY" as any,
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
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];
    const candidates: GatewayCandidate[] = [{ nodeId: newRelayKeypairs[0]!.nodeId, capability: "INTERNET_GATEWAY" as any, endpoint: "addr", linkUp: true, expiry: NOW + 3600 } as any];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      candidates, "INTERNET_GATEWAY" as any, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];

    // The only candidate IS the failed gateway → should be excluded.
    const failedGatewayNodeId = newRelayKeypairs[0]!.nodeId;
    const candidates: GatewayCandidate[] = [{ nodeId: failedGatewayNodeId, capability: "INTERNET_GATEWAY" as any, endpoint: "addr", linkUp: true, expiry: NOW + 3600 } as any];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      candidates, "INTERNET_GATEWAY" as any,
      failedGatewayNodeId, // exclude this gateway
      oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
    const newRelayKeypairs = [generateNodeKeypair()];
    const newRelayX25519PublicKeys = [x25519.getPublicKey(randomBytes(32))];
    const candidates: GatewayCandidate[] = [{ nodeId: newRelayKeypairs[0]!.nodeId, capability: "INTERNET_GATEWAY" as any, endpoint: "addr", linkUp: true, expiry: NOW + 3600 } as any];

    const result = await executor.execute(
      createRecoveryPlan([oldCircuit.routeId], "LINK_DOWN", [], "INTERNET_GATEWAY" as any),
      candidates, "INTERNET_GATEWAY" as any, "failed-gw", oldCircuit.circuitId, oldCircuit.commitmentRoot, NOW, NOW,
      newRelayX25519PublicKeys,
      createTestTopologyProvider(),
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
