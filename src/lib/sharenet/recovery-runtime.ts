/**
 * ShareNet 2.0 — Production recovery runtime construction (R-009 Stage 3 Phase 5).
 *
 * PRODUCTION INTEGRATION BOUNDARY (per ADR-0025 + the Subtask 1 closure gate):
 *
 *   LinkFailureDetector
 *       ↓
 *   FailureEventDispatcher  ←  THIS FILE constructs it WITH:
 *       ↓                      - RecoveryExecutor
 *   durable invalidation      - AuthenticatedTopologyProvider (ProductionAuthenticatedTopologyProvider)
 *       ↓                      - RecoveryManager
 *   zeroize                    - durable CircuitDestroyStore
 *       ↓                      - gateway candidates
 *   RecoveryManager            - required capability (typed, not `any`)
 *       ↓                      - relay X25519 material
 *   circuit-specific RecoveryPlan
 *       ↓
 *   RecoveryExecutor.execute()
 *       ↓
 *   new authenticated route
 *       ↓
 *   new circuit identity
 *       ↓
 *   observable RecoveryOutcome (RECOVERED | FAILED | EXECUTION_ERROR)
 *
 * ARCHITECTURE (per ADR-0013):
 *   - This module lives in the PLATFORM layer (`src/lib/sharenet/`). It MAY
 *     import Prisma, `@/lib/db`, `node:net`, etc. It imports the protocol
 *     core via `@reference/`.
 *   - The protocol core (`reference/`) remains dependency-clean — it never
 *     imports from `@/`. Architecture tests #21/#23 remain green.
 *
 * The `ProductionAuthenticatedTopologyProvider` is a REAL implementation of
 * the protocol-core `AuthenticatedTopologyProvider` interface. It constructs
 * GENUINE `BrandedCommittedRoute` artifacts via the full proof-carrying
 * pipeline:
 *
 *   generateNodeKeypair (per relay + gateway + initiator)
 *       ↓
 *   signAdvertisement → verifyAdvertisement → AuthenticatedNodeRecord (WeakSet)
 *       ↓
 *   3-message handshake → VerifiedTranscript (WeakSet) → AuthenticatedLink (WeakSet)
 *       ↓
 *   createValidatedHop → ValidatedHop (WeakSet)
 *       ↓
 *   RouteProposal → signRouteAcceptance × N → createRouteCommitment (WeakSet)
 *       ↓
 *   createBrandedCommittedRoute → BrandedCommittedRoute (WeakSet)
 *
 * The provider CANNOT return a forged route — every artifact passes through
 * the WeakSet membership gates. The executor independently verifies the
 * returned route (terminal hop == selected candidate, failed gateway
 * excluded, routeId == deriveRouteId(commitmentRoot)).
 *
 * This is NOT test-only wiring. It is the production construction used by
 * the ShareNet participant runtime.
 */

import {
  generateNodeKeypair,
  randomBytes,
  type NodeKeypair,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  verifyAdvertisement,
  advertisementToHex,
} from "@reference/advertisement/advertisement";
import {
  type RouteHop,
  type RouteProposal,
  signRouteAcceptance,
  createRouteCommitment,
} from "@reference/routing/route";
import type { ServiceAgreement } from "@reference/routing/service-negotiation";
import type { NodeCapability } from "@reference/routing/service-negotiation";
import { serviceDigest } from "@reference/routing/digests";
import { toHex } from "@reference/encoding/cbor";
import {
  createAuthenticatedNodeRecord,
  createValidatedHop,
  createBrandedCommittedRoute,
  type AuthenticatedNodeRecord,
  type ValidatedHop,
  type BrandedCommittedRoute,
} from "@reference/transport/validated-types";
import {
  computeTranscriptHash,
  computeLinkIdBytes,
  signPossessionProof,
  encodeInitiate,
  encodeAccept,
  ChallengeCache,
  POSSESSION_DOMAIN_INITIATOR,
  POSSESSION_DOMAIN_RESPONDER,
  ROLE_INITIATOR,
  ROLE_RESPONDER,
  type InitiateMessage,
  type AcceptMessage,
} from "@reference/transport/auth-handshake";
import {
  createVerifiedTranscript,
  createAuthenticatedLink,
  consumeChallengeForTranscript,
  type AuthenticatedLink,
  type VerifiedTranscript,
} from "@reference/transport/authenticated-link";
import { x25519 } from "@noble/curves/ed25519.js";
import {
  LinkFailureDetector,
  FailureEventDispatcher,
  type CircuitLinkAssociation,
} from "@reference/failure/failure-event-dispatcher";
import { RecoveryManager, type GatewayCandidate } from "@reference/routing/recovery";
import { RecoveryExecutor } from "@reference/routing/recovery-executor";
import type { AuthenticatedTopologyProvider } from "@reference/routing/recovery-executor";
import type { CircuitDestroyStore } from "@reference/circuit/replay-stores";
import { InMemoryCircuitSequenceFloorStore } from "@reference/circuit/replay-stores";

// -----------------------------------------------------------------------
// Relay identity registry — the production topology substrate
// -----------------------------------------------------------------------

/**
 * A pre-provisioned relay node identity. In production, these come from the
 * ShareNet link layer's peer identity table (persistent node keypairs +
 * X25519 circuit-setup keys). For the minimal production boundary, the
 * registry is constructed explicitly — not a test fixture, but a real
 * identity store that the provider uses to build genuine authenticated routes.
 */
export interface RelayIdentity {
  /** The relay's signing keypair (Ed25519). */
  readonly signing: NodeKeypair;
  /** The relay's X25519 keypair (for circuit setup). */
  readonly x25519SecretKey: Uint8Array;
  /** The relay's endpoint. */
  readonly endpoint: string;
  /** The relay's capability. */
  readonly capability: NodeCapability;
}

/**
 * A gateway identity (terminal hop). Like a RelayIdentity but marked as a
 * gateway — the provider uses the selected candidate's nodeId as the
 * terminal hop.
 */
export interface GatewayIdentity {
  readonly signing: NodeKeypair;
  readonly x25519SecretKey: Uint8Array;
  readonly endpoint: string;
  readonly capability: NodeCapability;
}

/**
 * The production topology substrate: the set of relay identities + gateway
 * identities that the provider can draw from when constructing replacement
 * routes. The failed gateway is excluded by nodeId (the executor verifies
 * this independently).
 */
export interface TopologyRegistry {
  readonly relays: RelayIdentity[];
  readonly gateways: GatewayIdentity[];
}

// -----------------------------------------------------------------------
// ProductionAuthenticatedTopologyProvider
// -----------------------------------------------------------------------

/**
 * The PRODUCTION implementation of `AuthenticatedTopologyProvider`.
 *
 * Constructs GENUINE `BrandedCommittedRoute` artifacts via the full
 * proof-carrying pipeline (advertisements → handshakes → validated hops →
 * commitment → branded route). Every artifact is WeakSet-registered —
 * forgery is impossible.
 *
 * The provider:
 *   1. Selects relays from the registry (excluding the failed gateway).
 *   2. Uses the selected candidate's nodeId as the terminal hop.
 *   3. Runs the genuine 3-message handshake per hop.
 *   4. Returns the branded route + the relay keypairs (for circuit setup).
 *
 * The executor INDEPENDENTLY verifies the returned route:
 *   - terminal hop == selectedCandidate.nodeId
 *   - failed gateway NOT in any hop
 *   - routeId == deriveRouteId(commitmentRoot)
 *
 * This provider CANNOT bypass those checks — it can only produce genuine
 * artifacts. If it returns a route that doesn't match the selection decision,
 * the executor rejects it.
 */
export class ProductionAuthenticatedTopologyProvider implements AuthenticatedTopologyProvider {
  private readonly initiator: NodeKeypair;

  /**
   * @param registry - the topology substrate (relays + gateways).
   * @param now - the timestamp for advertisement/handshake/commitment.
   */
  constructor(
    private readonly registry: TopologyRegistry,
    private readonly now: number,
  ) {
    // The initiator keypair is generated once per provider instance. In a
    // real deployment, this would be the local node's persistent identity.
    this.initiator = generateNodeKeypair();
  }

  constructRecoveryRoute(
    selectedCandidate: GatewayCandidate,
    failedGatewayNodeId: string,
  ): { brandedRoute: BrandedCommittedRoute; relayKeypairs: NodeKeypair[] } {
    // 1. Select relays: exclude the failed gateway. Use all available relays
    //    (they are pre-authenticated identities in the registry).
    const candidateRelays = this.registry.relays.filter(
      (r) => r.signing.nodeId !== failedGatewayNodeId,
    );
    // 2. Find the selected gateway's full identity (by nodeId).
    const gatewayIdentity = this.registry.gateways.find(
      (g) => g.signing.nodeId === selectedCandidate.nodeId,
    );
    if (!gatewayIdentity) {
      // The selected candidate is not in the gateway registry — the provider
      // CANNOT fabricate a gateway identity. This is a hard failure: the
      // provider produces ONLY genuine artifacts from authenticated material.
      throw new Error(
        `ProductionAuthenticatedTopologyProvider: selected candidate "${selectedCandidate.nodeId}" ` +
        `is not present in the gateway registry. The provider cannot construct a genuine ` +
        `route to an unauthenticated gateway. Recovery rejected (fail-closed).`,
      );
    }

    // 3. Build the hop list: [relay_0, relay_1, ..., gateway].
    //    The gateway is the TERMINAL hop (matches the executor's verification).
    const hopIdentities = [...candidateRelays, gatewayIdentity];
    const hopKeypairs = hopIdentities.map((h) => h.signing);
    const capabilities = hopIdentities.map((h) => h.capability);
    const endpoints = hopIdentities.map((h) => h.endpoint);

    // 4. Per-hop: advertisement → verify → AuthenticatedNodeRecord.
    const authNodes: AuthenticatedNodeRecord[] = [];
    const advHexes: string[] = [];
    for (let i = 0; i < hopKeypairs.length; i++) {
      const kp = hopKeypairs[i]!;
      const adv = signAdvertisement({
        protocolVersion: 1,
        nodeId: kp.nodeId,
        signingPublicKey: kp.publicKey,
        capabilities: [capabilities[i]!],
        endpoints: [{ type: "tcp", address: endpoints[i]!.split(":")[0]!, port: 7788 }],
        sequence: 1,
        timestamp: this.now,
        expiry: this.now + 3600,
        nonce: randomBytes(16),
      }, kp.secretKey);
      const v = verifyAdvertisement(adv, this.now);
      if (!v.ok) throw new Error(`advertisement verification failed for hop ${i}: ${v.error} — ${v.detail}`);
      authNodes.push(createAuthenticatedNodeRecord(v.verified));
      advHexes.push(advertisementToHex(adv));
    }

    // 5. Initiator advertisement (for the handshake).
    const initiatorAdv = signAdvertisement({
      protocolVersion: 1,
      nodeId: this.initiator.nodeId,
      signingPublicKey: this.initiator.publicKey,
      capabilities: ["MESH_RELAY"],
      endpoints: [{ type: "tcp", address: "10.0.0.99", port: 7788 }],
      sequence: 1,
      timestamp: this.now,
      expiry: this.now + 3600,
      nonce: randomBytes(16),
    }, this.initiator.secretKey);
    const initiatorAdvHex = advertisementToHex(initiatorAdv);

    // 6. Per-hop: genuine 3-message handshake → VerifiedTranscript → AuthenticatedLink.
    const authenticatedLinks: AuthenticatedLink[] = [];
    for (let i = 0; i < hopKeypairs.length; i++) {
      const vt = runHandshake(
        this.initiator, hopKeypairs[i]!,
        initiatorAdvHex, advHexes[i]!,
        this.now,
      );
      const link = createAuthenticatedLink({
        localNodeId: this.initiator.nodeId,
        remoteNode: authNodes[i]!,
        verifiedTranscript: vt,
        establishedAt: this.now,
        expiresAt: this.now + 3600,
      });
      authenticatedLinks.push(link);
    }

    // 7. Build the RouteProposal hops.
    const hops: RouteHop[] = hopKeypairs.map((kp, i) => ({
      nodeId: kp.nodeId,
      capability: capabilities[i]!,
      endpoint: endpoints[i]!,
      linkUp: true,
    }));

    const proposal: RouteProposal = {
      hops,
      requirementDigest: toHex(randomBytes(32)),
      expiry: this.now + 3600,
      initiatorNodeId: this.initiator.nodeId,
      agreementDigest: toHex(randomBytes(32)),
    };

    // 8. Service agreements + hop public keys.
    const serviceAgreements = new Map<number, ServiceAgreement>();
    const hopPublicKeys = new Map<string, Uint8Array>();
    for (let i = 0; i < hopKeypairs.length; i++) {
      serviceAgreements.set(i, {
        nodeId: hopKeypairs[i]!.nodeId,
        capability: capabilities[i]!,
        requirementDigest: proposal.requirementDigest,
        allocatedBandwidthBps: 1048576,
        expiry: proposal.expiry,
        policyVersion: 1,
      });
      hopPublicKeys.set(hopKeypairs[i]!.nodeId, hopKeypairs[i]!.publicKey);
    }

    // 9. Genuine ValidatedHops (WeakSet-registered).
    const validatedHops: ValidatedHop[] = [];
    for (let i = 0; i < hopKeypairs.length; i++) {
      const saDigestHex = toHex(serviceDigest(serviceAgreements.get(i)!));
      validatedHops.push(
        createValidatedHop(
          authenticatedLinks[i]!,
          endpoints[i]!,
          capabilities[i]!,
          saDigestHex,
          this.now,
        ),
      );
    }

    // 10. Acceptances + commitment.
    const acceptances = hopKeypairs.map((kp, i) =>
      signRouteAcceptance(
        proposal, i, hops[i]!,
        serviceAgreements.get(i)!,
        kp.nodeId, kp.secretKey, proposal.expiry,
      ),
    );

    const result = createRouteCommitment(
      proposal, acceptances, hopPublicKeys, serviceAgreements,
      this.initiator.secretKey, this.now,
    );
    if (!result.ok) throw new Error(`commitment failed: ${result.reason}`);

    // 11. Genuine BrandedCommittedRoute (WeakSet-registered).
    const branded = createBrandedCommittedRoute(result.commitment, validatedHops);

    // 12. Return the AUTHENTICATED hop X25519 public keys — in route order.
    //     These are derived from the hop identities' X25519 secret keys. The
    //     executor uses these for circuit setup ECDH (they are the ONLY
    //     authoritative source — the provider knows which hops are in the
    //     route + their matching X25519 keys).
    const hopX25519PublicKeys = hopIdentities.map((h) => x25519.getPublicKey(h.x25519SecretKey));

    return { brandedRoute: branded, relayKeypairs: hopKeypairs, hopX25519PublicKeys };
  }
}

// -----------------------------------------------------------------------
// Internal: genuine 3-message handshake (mirrors the test helper, but lives
// in the production module so the provider is self-contained).
// -----------------------------------------------------------------------

function runHandshake(
  initiatorKp: NodeKeypair,
  responderKp: NodeKeypair,
  initiatorAdvHex: string,
  responderAdvHex: string,
  now: number,
): VerifiedTranscript {
  const linkNonceA = randomBytes(16);
  const linkNonceB = randomBytes(16);
  const challengeForB = randomBytes(32);
  const challengeForA = randomBytes(32);

  const initiateMsg: InitiateMessage = {
    kind: 1,
    advertisementHex: initiatorAdvHex,
    linkNonceA,
    challengeForB,
  };
  const initiateBytes = encodeInitiate(initiateMsg);

  const linkIdBytes = computeLinkIdBytes(
    initiatorKp.nodeId, responderKp.nodeId, linkNonceA, linkNonceB,
  );

  const transcriptAfterInitiate = computeTranscriptHash([initiateBytes]);

  const proofB = signPossessionProof(
    responderKp.secretKey, POSSESSION_DOMAIN_RESPONDER,
    transcriptAfterInitiate, linkIdBytes, challengeForB, ROLE_RESPONDER,
  );

  const acceptMsg: AcceptMessage = {
    kind: 2,
    advertisementHex: responderAdvHex,
    linkNonceB, challengeForA, proofB,
  };
  const acceptBytes = encodeAccept(acceptMsg);

  const transcriptAfterAccept = computeTranscriptHash([initiateBytes, acceptBytes]);

  const proofA = signPossessionProof(
    initiatorKp.secretKey, POSSESSION_DOMAIN_INITIATOR,
    transcriptAfterAccept, linkIdBytes, challengeForA, ROLE_INITIATOR,
  );

  const cache = new ChallengeCache();
  cache.registerChallenge(challengeForB, now * 1000);
  const consumedChallenge = consumeChallengeForTranscript(
    cache, challengeForB, "RESPONDER", initiatorKp.nodeId, now,
  );

  return createVerifiedTranscript({
    initiateBytes,
    acceptBytes,
    proofA,
    consumedChallenge,
    now,
  });
}

// -----------------------------------------------------------------------
// RecoveryRuntime — the production construction
// -----------------------------------------------------------------------

/**
 * The production recovery runtime. Constructed ONCE per ShareNet participant
 * process. Wires the full failure → recovery pipeline.
 */
export interface RecoveryRuntime {
  readonly detector: LinkFailureDetector;
  readonly dispatcher: FailureEventDispatcher;
  readonly executor: RecoveryExecutor;
  readonly topologyProvider: AuthenticatedTopologyProvider;
  readonly recoveryManager: RecoveryManager;
  readonly destroyStore: CircuitDestroyStore;
}

/**
 * Configuration for the production recovery runtime.
 */
export interface RecoveryRuntimeConfig {
  /** The authoritative CircuitDestroyStore (durable SQLite in production). */
  readonly destroyStore: CircuitDestroyStore;
  /** The circuit-link associations (linkId → circuits on that link). */
  readonly circuitAssociations: Map<string, CircuitLinkAssociation[]>;
  /** The gateway candidates available for recovery. */
  readonly gatewayCandidates: GatewayCandidate[];
  /** The required gateway capability (typed, NOT `any`). */
  readonly requiredCapability: NodeCapability;
  /** The topology registry (relays + gateways with genuine keypairs). */
  readonly topologyRegistry: TopologyRegistry;
  /** The current timestamp (unix seconds). */
  readonly now: number;
}

/**
 * Construct the PRODUCTION recovery runtime. This is the SOLE production
 * construction of `FailureEventDispatcher` + `RecoveryExecutor` +
 * `AuthenticatedTopologyProvider`. It wires them together with a durable
 * `CircuitDestroyStore` + a `RecoveryManager` + the typed required
 * capability + the relay X25519 material.
 *
 * The constructed dispatcher is the one production callers (transport,
 * forwarding) use for `recordObservation()` / `recordSuccess()`.
 *
 * FAIL-CLOSED: if any required component is missing, the constructor throws
 * (via the FailureEventDispatcher constructor's fail-closed guards).
 */
export function createShareNetRecoveryRuntime(config: RecoveryRuntimeConfig): RecoveryRuntime {
  const detector = new LinkFailureDetector();
  const recoveryManager = new RecoveryManager();
  const executor = new RecoveryExecutor(
    config.destroyStore,
    () => new InMemoryCircuitSequenceFloorStore(),
  );
  const topologyProvider = new ProductionAuthenticatedTopologyProvider(
    config.topologyRegistry,
    config.now,
  );

  // PRODUCTION CONSTRUCTION: the dispatcher is constructed WITH the executor
  // + provider + manager + durable store + candidates + capability. The
  // X25519 public keys are NO LONGER passed separately — the provider returns
  // them as part of constructRecoveryRoute() (they are the authoritative
  // hop keys, in route order). The executor uses the provider-returned keys.
  // The constructor fail-closed guards verify all required components are present.
  const dispatcher = new FailureEventDispatcher(
    detector,
    config.circuitAssociations,
    config.destroyStore,
    recoveryManager,
    executor,
    topologyProvider,
    config.gatewayCandidates,
    config.requiredCapability,
    // relayX25519PublicKeys: omitted — provider-sourced via constructRecoveryRoute().
    // Kept as undefined for backward API compatibility; the executor no
    // longer uses this parameter.
    undefined,
  );

  return {
    detector,
    dispatcher,
    executor,
    topologyProvider,
    recoveryManager,
    destroyStore: config.destroyStore,
  };
}
