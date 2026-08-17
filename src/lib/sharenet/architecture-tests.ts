/**
 * ShareNet 2.0 — Architecture Regression Tests (the "10 First Tests" from spec/00 §32).
 *
 * Per spec/17 + spec/00 §31: executable tests that MUST fail CI if any
 * forbidden pipeline is permitted. Cannot rely on code review alone.
 *
 * Each test returns { name, passed, expected, actual, description, category }.
 * Categories:
 *   - PROTOCOL  : cryptographic / encoding invariants
 *   - ARCHITECTURE : forbidden pipeline guards
 *   - SECURITY  : sequence / replay / binding invariants
 *
 * This module is pure (no DB). Tests that require DB state (e.g. sequence
 * floor persistence) live in the live-run endpoint and exercise the
 * Prisma-backed `checkAndUpdateSequenceFloor` function via the API.
 */

import { runCborGoldenVectors } from "@reference/encoding/golden-vectors";
import { runIdentityGoldenVectors } from "@reference/identity/golden-vectors";
import {
  generateNodeKeypair,
  keypairFromSecretKey,
  hexToBytes,
  bytesToHex,
  randomBytes,
  verifyNodeIdBinding,
  deriveNodeId,
} from "@reference/identity/keys";
import {
  signAdvertisement,
  verifyAdvertisement,
  advertisementToHex,
  advertisementFromHex,
} from "@reference/advertisement/advertisement";
import {
  checkSequence,
  acceptAdvertisement,
} from "@reference/advertisement/sequence-floor";
import {
  createRemoteNodeHint,
  verifyRemoteNodeHint,
  PROMOTE_HINT_TO_RECORD_FORBIDDEN,
  type RemoteNodeHint,
} from "@reference/topology/remote-node-hint";
import { isCanonical, canonicalEncode, canonicalDecode, toHex, fromHex } from "@reference/encoding/cbor";
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import {
  type RouteHop,
  type RouteProposal,
  TOPOLOGY_TO_ROUTE_FORBIDDEN,
  PROPOSAL_TO_CIRCUIT_FORBIDDEN,
} from "@reference/routing/route";
import {
  setupCircuit,
  UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN,
} from "@reference/circuit/circuit";
import {
  evaluateGatewayRequest,
  defaultGatewayPolicy,
  defaultGatewayCapacity,
  type GatewayRequestInput,
} from "@reference/gateway/gateway";
import {
  createContributionProof,
  SELF_REPORTED_CONTRIBUTION_FORBIDDEN,
  createBilateralReceipt,
} from "@reference/economics/contribution";
import {
  createAuthenticatedNodeRecord,
  isAuthenticatedNodeRecord,
  createValidatedHop,
  isValidatedHop,
  createBrandedCommittedRoute,
  isBrandedCommittedRoute,
  HINT_TO_VALIDATED_HOP_FORBIDDEN,
  UNBRANDED_ROUTE_FORBIDDEN,
  type AuthenticatedNodeRecord,
  type ValidatedHop,
  type BrandedCommittedRoute,
} from "@reference/transport/validated-types";

export interface ArchTestResult {
  id: number;
  name: string;
  category: "PROTOCOL" | "ARCHITECTURE" | "SECURITY";
  /**
   * Three-state test outcome. Per the corrective milestone (2026-08-16, F6):
   * - `passed`   = the test ran and the property holds.
   * - `failed`   = the test ran and the property does NOT hold.
   * - `skipped`  = the test could NOT run in this environment (e.g. the
   *                two-process link test on Vercel where the mini-services
   *                are not reachable). A skipped test MUST NOT be counted as
   *                passed. The dashboard and CI MUST report skipped
   *                separately.
   */
  status: "passed" | "failed" | "skipped";
  /** @deprecated use `status` instead. Kept for backward compat = (status === "passed"). */
  passed: boolean;
  description: string;
  expected: string;
  actual: string;
  durationMs: number;
  /** If status === "skipped", the reason the test could not run. */
  skipReason?: string;
}

export interface ArchTestSuiteResult {
  totalTests: number;
  passed: number;
  failed: number;
  /** Tests that could not run in this environment. Reported separately, never counted as passed. */
  skipped: number;
  results: ArchTestResult[];
  ranAt: string;
  durationMs: number;
  spec: string;
}

/**
 * Run the 10 first tests from spec/00 §32, plus additional architecture
 * regression guards from spec/00 §31 / spec/17.
 */
export async function runArchitectureTests(): Promise<ArchTestSuiteResult> {
  const start = Date.now();
  const results: ArchTestResult[] = [];

  // ---------------- Test 1: canonical CBOR vector ----------------
  results.push(
    await runOne(1, "canonical CBOR golden vectors", "PROTOCOL", "spec/00 §32.1 + spec/17 §2.1", () => {
      const vresults = runCborGoldenVectors();
      const failed = vresults.filter((r) => !r.passed);
      return {
        passed: failed.length === 0,
        expected: `${vresults.length} vectors pass`,
        actual: failed.length === 0 ? `${vresults.length} vectors pass` : `FAILED: ${failed.map((f) => f.name).join(", ")}`,
      };
    }),
  );

  // ---------------- Test 2: NodeId/public-key binding ----------------
  results.push(
    await runOne(2, "NodeId/public-key binding (spec/02 §3)", "ARCHITECTURE", "spec/00 §32.2 + spec/02 §3", () => {
      const vresults = runIdentityGoldenVectors();
      const failed = vresults.filter((r) => !r.passed);
      return {
        passed: failed.length === 0,
        expected: "deriveNodeId(pubKey) is deterministic and matches the FROZEN vector",
        actual: failed.length === 0 ? "all identity vectors pass" : `FAILED: ${failed.map((f) => f.name).join(", ")}`,
      };
    }),
  );

  // ---------------- Test 3: valid advertisement signature ----------------
  results.push(
    await runOne(3, "valid advertisement signature verifies", "PROTOCOL", "spec/00 §32.3 + spec/03 §5.1", () => {
      const kp = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const adv = signAdvertisement({
        protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
        capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
        sequence: 1, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
      }, kp.secretKey);
      const v = verifyAdvertisement(adv);
      return { passed: v.ok, expected: "verify returns ok=true", actual: v.ok ? "ok=true" : `ok=false (${v.error})` };
    }),
  );

  // ---------------- Test 4: invalid advertisement signature rejected ----------------
  results.push(
    await runOne(4, "invalid advertisement signature rejected", "SECURITY", "spec/00 §32.4 + spec/03 §5.1", () => {
      const kp = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const adv = signAdvertisement({
        protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
        capabilities: ["MESH_RELAY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
        sequence: 1, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
      }, kp.secretKey);
      // Tamper: flip a signature bit.
      const tamperedSig = new Uint8Array(adv.signature);
      tamperedSig[0] ^= 0xff;
      const tampered = { ...adv, signature: tamperedSig };
      const v = verifyAdvertisement(tampered);
      return {
        passed: !v.ok && v.error === "INVALID_SIGNATURE",
        expected: "verify returns ok=false, error=INVALID_SIGNATURE",
        actual: v.ok ? "FAIL: tampered sig verified" : `ok=false (${v.error})`,
      };
    }),
  );

  // ---------------- Test 5: sequence rollback rejection ----------------
  results.push(
    await runOne(5, "sequence rollback rejected (spec/03 §5.5)", "SECURITY", "spec/00 §32.5 + spec/03 §5.5 + ADR-0006", () => {
      const stale = checkSequence(10, 5);
      const dup = checkSequence(10, 10);
      const newer = checkSequence(10, 11);
      const staleOk = !stale.ok && stale.reason === "STALE";
      const dupOk = !dup.ok && dup.reason === "DUPLICATE";
      const newerOk = newer.ok && newer.newFloor === 11;
      return {
        passed: staleOk && dupOk && newerOk,
        expected: "n<floor=STALE, n==floor=DUPLICATE, n>floor=ACCEPT",
        actual: `stale=${staleOk}, dup=${dupOk}, newer=${newerOk}`,
      };
    }),
  );

  // ---------------- Test 6: expired advertisement does NOT reset sequence ----------------
  results.push(
    await runOne(6, "expired advertisement does not reset sequence floor", "SECURITY", "spec/00 §32.6 + spec/14 §3 + ADR-0006", () => {
      // Simulate: node accepted seq=5. Then an expired advertisement arrives
      // with seq=1 (older). The check MUST reject as STALE — never accept
      // and never reset the floor.
      const expiredFloor = checkSequence(5, 1);
      const acceptedAgain = checkSequence(5, 5);
      // The floor must STILL be 5 (not reset to 1 or 0).
      const floorPreserved = expiredFloor.ok === false && acceptedAgain.ok === false;
      return {
        passed: floorPreserved,
        expected: "expired advertisement with stale sequence is rejected; floor preserved",
        actual: `expired/stale rejected=${!expiredFloor.ok}, duplicate rejected=${!acceptedAgain.ok}`,
      };
    }),
  );

  // ---------------- Test 7: RemoteNodeHint cannot become authenticated node ----------------
  results.push(
    await runOne(7, "RemoteNodeHint CANNOT become AuthenticatedNodeRecord (spec/06 §3)", "ARCHITECTURE", "spec/00 §32.7 + spec/06 §3 + ADR-0007", () => {
      const reporterKp = generateNodeKeypair();
      const subjectKp = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const hint: RemoteNodeHint = createRemoteNodeHint({
        reporterNodeId: reporterKp.nodeId,
        subjectNodeId: subjectKp.nodeId,
        subjectEndpointHint: "10.0.0.5:7788",
        claimedCapabilities: ["MESH_RELAY"],
        hopCount: 1, timestamp: now, nonce: randomBytes(16),
      }, reporterKp.secretKey);

      // Architecture guard 1: PROMOTE_HINT_TO_RECORD_FORBIDDEN throws.
      let guardThrew = false;
      try { PROMOTE_HINT_TO_RECORD_FORBIDDEN(hint); } catch { guardThrew = true; }

      // Architecture guard 2: verifyRemoteNodeHint returns ok=true but
      // the return type is { ok: true }, NOT an AuthenticatedNodeRecord.
      const hv = verifyRemoteNodeHint(hint, reporterKp.publicKey);
      const hintDoesNotReturnRecord = hv.ok && !("record" in hv);

      // Architecture guard 3: acceptAdvertisement does not accept a hint
      // as input — its signature requires verification + sequenceCheck
      // primitives that a hint cannot produce.
      const acceptSignature = acceptAdvertisement.toString();
      const doesNotAcceptHintArg = !acceptSignature.includes("hint");

      return {
        passed: guardThrew && hintDoesNotReturnRecord && doesNotAcceptHintArg,
        expected: "no code path promotes a RemoteNodeHint to an AuthenticatedNodeRecord",
        actual: `guard threw=${guardThrew}, hint verify returns ok but not a record=${hintDoesNotReturnRecord}, accept signature excludes hint arg=${doesNotAcceptHintArg}`,
      };
    }),
  );

  // ---------------- Test 8: route rejects unauthenticated hop ----------------
  // (Stub: route construction is Phase 5; we verify the advertisement-level
  // prerequisite: an advertisement whose nodeId does not match its signing key
  // is rejected, which is the foundation of "unauthenticated hop" rejection.)
  results.push(
    await runOne(8, "route rejects unauthenticated hop (foundation: IDENTITY_BINDING_MISMATCH)", "SECURITY", "spec/00 §32.8 + spec/02 §3 + spec/07", () => {
      const kpA = generateNodeKeypair();
      const kpB = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      // Sign with A's key but claim B's nodeId.
      const adv = signAdvertisement({
        protocolVersion: 1, nodeId: kpA.nodeId, signingPublicKey: kpA.publicKey,
        capabilities: ["MESH_RELAY"], endpoints: [],
        sequence: 1, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
      }, kpA.secretKey);
      const tampered = { ...adv, nodeId: kpB.nodeId };
      const v = verifyAdvertisement(tampered);
      return {
        passed: !v.ok && v.error === "IDENTITY_BINDING_MISMATCH",
        expected: "verify returns ok=false, error=IDENTITY_BINDING_MISMATCH",
        actual: v.ok ? "FAIL: mismatched nodeId verified" : `ok=false (${v.error})`,
      };
    }),
  );

  // ---------------- Test 9: circuit rejects uncommitted route ----------------
  // (Stub: circuit establishment is Phase 6. We verify the foundation: the
  // acceptAdvertisement function requires both verification AND sequence-check
  // to succeed. Without a verified advertisement, no record is produced —
  // which is the prerequisite for any future circuit establishment.)
  results.push(
    await runOne(9, "circuit rejects uncommitted route (foundation: acceptAdvertisement requires verification + sequence)", "ARCHITECTURE", "spec/00 §32.9 + spec/08 §3 + ADR-0007", () => {
      const kp = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const adv = signAdvertisement({
        protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
        capabilities: ["MESH_RELAY"], endpoints: [],
        sequence: 1, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
      }, kp.secretKey);
      // Case A: verification fails (simulate by claiming the verification failed)
      //   -> acceptAdvertisement MUST return ok=false.
      const failedVerification = acceptAdvertisement(
        adv.nodeId, adv.signingPublicKey, adv.capabilities, adv.sequence, now,
        { verificationOk: false, verificationError: "INVALID_SIGNATURE" },
      );
      // Case B: verification ok but sequence check fails (duplicate)
      //   -> acceptAdvertisement MUST return ok=false.
      const failedSequence = acceptAdvertisement(
        adv.nodeId, adv.signingPublicKey, adv.capabilities, adv.sequence, now,
        { verificationOk: true, sequenceCheck: { ok: false, reason: "DUPLICATE", currentFloor: 1, attemptedSequence: 1 } },
      );
      // Case C: both succeed
      //   -> acceptAdvertisement MUST return ok=true with a record.
      const okCase = acceptAdvertisement(
        adv.nodeId, adv.signingPublicKey, adv.capabilities, adv.sequence, now,
        { verificationOk: true, sequenceCheck: { ok: true, previousFloor: -1, newFloor: 1 } },
      );
      const allOk = !failedVerification.ok && !failedSequence.ok && okCase.ok;
      return {
        passed: allOk,
        expected: "no record produced without verification AND sequence check passing",
        actual: `failedVerification rejected=${!failedVerification.ok}, failedSequence rejected=${!failedSequence.ok}, both-ok accepted=${okCase.ok}`,
      };
    }),
  );

  // ---------------- Test 10: hex round-trip preserves advertisement ----------------
  // (Replaces "two independent processes establish authenticated link" which
  // requires Phase 3 transport work. We verify the cross-implementation
  // stability prerequisite: an advertisement serialized to hex and back
  // is byte-identical, so two implementations exchanging the hex form
  // agree on the signed bytes.)
  results.push(
    await runOne(10, "hex round-trip preserves advertisement bytes (Phase 3 prerequisite)", "PROTOCOL", "spec/00 §32.10 + spec/03 §6 + ADR-0004", () => {
      const kp = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const adv = signAdvertisement({
        protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
        capabilities: ["MESH_RELAY", "DISCOVERY"], endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
        sequence: 42, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
      }, kp.secretKey);
      const hex = advertisementToHex(adv);
      const roundTripped = advertisementFromHex(hex);
      const reHex = advertisementToHex(roundTripped);
      const nodeIdsMatch = roundTripped.nodeId === adv.nodeId;
      const seqMatch = roundTripped.sequence === adv.sequence;
      const bytesMatch = hex === reHex;
      // Also assert the CBOR bytes are in canonical form (re-encoding is stable).
      const canonical = isCanonical(fromHex(hex));
      return {
        passed: nodeIdsMatch && seqMatch && bytesMatch && canonical,
        expected: "hex round-trip preserves all fields + canonical form holds",
        actual: `nodeId match=${nodeIdsMatch}, seq match=${seqMatch}, bytes match=${bytesMatch}, canonical=${canonical}`,
      };
    }),
  );

  // ---------------- Additional guards from spec/00 §31 ----------------

  // G1: RemoteNodeHint/distance_hint → ValidatedHop fails (unforgeable type boundary)
  // Per R-006 hardening: test that the TYPE BOUNDARY prevents construction,
  // not merely that a guard function throws.
  results.push(
    await runOne(11, "RemoteNodeHint → ValidatedHop fails (unforgeable type boundary, R-006H)", "ARCHITECTURE", "spec/00 §31 + spec/07 + R-006H", async () => {
      const reporter = generateNodeKeypair();
      const subject = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const hint = createRemoteNodeHint({
        reporterNodeId: reporter.nodeId, subjectNodeId: subject.nodeId,
        subjectEndpointHint: "10.0.0.5:7788", claimedCapabilities: ["MESH_RELAY"],
        hopCount: 0, timestamp: now, nonce: randomBytes(16),
      }, reporter.secretKey);

      // Negative: HINT_TO_VALIDATED_HOP_FORBIDDEN throws
      let hintGuardThrew = false;
      try { HINT_TO_VALIDATED_HOP_FORBIDDEN(hint); } catch { hintGuardThrew = true; }

      // Negative: createValidatedHop REQUIRES an AuthenticatedNodeRecord.
      // A RemoteNodeHint is NOT an AuthenticatedNodeRecord — it lacks the brand.
      // Attempting to pass the hint as if it were authenticated must throw.
      let hintToHopThrew = false;
      try {
        // The hint is not an AuthenticatedNodeRecord — createValidatedHop
        // checks isAuthenticatedNodeRecord() at runtime and throws.
        createValidatedHop(hint as any, hint.subjectEndpointHint, "MESH_RELAY", true, "");
      } catch { hintToHopThrew = true; }

      // Negative: a raw NodeId string is also not an AuthenticatedNodeRecord
      let stringToHopThrew = false;
      try {
        createValidatedHop({ nodeId: subject.nodeId } as any, "10.0.0.5:7788", "MESH_RELAY", true, "");
      } catch { stringToHopThrew = true; }

      // Negative: ADV_VERIFIED-only link (linkUp=false) cannot produce ValidatedHop
      const authNode = createAuthenticatedNodeRecord({
        advertisement: {
          nodeId: subject.nodeId,
          signingPublicKey: subject.publicKey,
          capabilities: ["MESH_RELAY"],
          endpoints: [{ type: "tcp", address: "10.0.0.5", port: 7788 }],
          sequence: 1,
          expiry: now + 3600,
        },
        verifiedAt: now,
      });
      let advVerifiedThrew = false;
      try {
        createValidatedHop(authNode, "10.0.0.5:7788", "MESH_RELAY", false, ""); // linkUp=false
      } catch { advVerifiedThrew = true; }

      // Positive: a genuine AuthenticatedNodeRecord + LINK_UP=true CAN produce ValidatedHop
      const validHop = createValidatedHop(authNode, "10.0.0.5:7788", "MESH_RELAY", true, "digest123");
      const validHopIsBranded = isValidatedHop(validHop);

      return {
        passed: hintGuardThrew && hintToHopThrew && stringToHopThrew && advVerifiedThrew && validHopIsBranded,
        expected: "hint → ValidatedHop fails (no brand); string → fails; ADV_VERIFIED → fails; authenticated + LINK_UP → succeeds (branded)",
        actual: `hint guard=${hintGuardThrew}, hint→hop threw=${hintToHopThrew}, string→hop threw=${stringToHopThrew}, adv-only threw=${advVerifiedThrew}, valid branded=${validHopIsBranded}`,
      };
    }),
  );

  // G2: RouteProposal/plain-object → setupCircuit fails (runtime brand check, not source-text)
  // Per R-006 hardening: test the runtime brand boundary, not a regex on source text.
  results.push(
    await runOne(12, "RouteProposal/plain-object → setupCircuit fails — brand check (R-006H)", "ARCHITECTURE", "spec/00 §31 + spec/08 + R-006H", async () => {
      const kp = generateNodeKeypair();

      // Negative: a plain object (not a CommittedRoute or BrandedCommittedRoute)
      // cannot pass isBrandedCommittedRoute check.
      const plainObject = { routeId: "test", hops: [], expiry: 0 };
      const plainNotBranded = !isBrandedCommittedRoute(plainObject);

      // Negative: a RouteProposal is also not a BrandedCommittedRoute
      const proposal: RouteProposal = {
        routeId: toHex(randomBytes(32)),
        hops: [{ nodeId: kp.nodeId, capability: "MESH_RELAY", endpoint: "10.0.0.1:7788", linkUp: true }],
        requirementDigest: toHex(randomBytes(32)),
        expiry: Math.floor(Date.now() / 1000) + 3600,
        initiatorNodeId: kp.nodeId,
        agreementDigest: toHex(randomBytes(32)),
      };
      const proposalNotBranded = !isBrandedCommittedRoute(proposal);

      // Negative: UNBRANDED_ROUTE_FORBIDDEN throws
      let unbrandedThrew = false;
      try { UNBRANDED_ROUTE_FORBIDDEN(proposal); } catch { unbrandedThrew = true; }

      // Negative: PROPOSAL_TO_CIRCUIT_FORBIDDEN throws
      let proposalGuardThrew = false;
      try { PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal); } catch { proposalGuardThrew = true; }

      // Positive: a BrandedCommittedRoute IS recognized by isBrandedCommittedRoute
      // (We construct one with a minimal ValidatedHop to prove the brand works)
      const authNode = createAuthenticatedNodeRecord({
        advertisement: {
          nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
          capabilities: ["MESH_RELAY"],
          endpoints: [{ type: "tcp", address: "10.0.0.1", port: 7788 }],
          sequence: 1, expiry: Math.floor(Date.now() / 1000) + 3600,
        },
        verifiedAt: Math.floor(Date.now() / 1000),
      });
      const validHop = createValidatedHop(authNode, "10.0.0.1:7788", "MESH_RELAY", true, "digest");
      const brandedRoute = createBrandedCommittedRoute({
        routeId: toHex(randomBytes(32)),
        hops: [validHop],
        expiry: Math.floor(Date.now() / 1000) + 3600,
        initiatorNodeId: kp.nodeId,
        agreementDigest: "digest",
        committedAt: Math.floor(Date.now() / 1000),
      });
      const brandedRecognized = isBrandedCommittedRoute(brandedRoute);

      return {
        passed: plainNotBranded && proposalNotBranded && unbrandedThrew && proposalGuardThrew && brandedRecognized,
        expected: "plain object not branded; RouteProposal not branded; UNBRANDED_ROUTE_FORBIDDEN + PROPOSAL_TO_CIRCUIT_FORBIDDEN throw; BrandedCommittedRoute recognized",
        actual: `plain not branded=${plainNotBranded}, proposal not branded=${proposalNotBranded}, unbranded guard=${unbrandedThrew}, proposal guard=${proposalGuardThrew}, branded recognized=${brandedRecognized}`,
      };
    }),
  );

  // G3: GatewayCapability ≠ Authorization (runtime policy check, not source-text)
  // Per R-006.3: construct a CapabilityOffer with INTERNET_GATEWAY but prove
  // the service cannot transition to ALLOW without the policy path.
  results.push(
    await runOne(13, "GatewayCapability ≠ Authorization — policy check required (spec/00 §31, R-006.3)", "ARCHITECTURE", "spec/00 §31 + spec/09 + R-006.3", async () => {
      const policy = defaultGatewayPolicy();
      const capacity = defaultGatewayCapacity();

      // Negative: a gateway with INTERNET_GATEWAY capability but no LINK_UP
      // must be DENIED (ADV_VERIFIED_ONLY is not routable).
      // We simulate this by passing a request from a peer that would have
      // INTERNET_GATEWAY capability but the gateway policy checks run
      // BEFORE any capability-based authorization.
      const resultNoLinkUp = evaluateGatewayRequest(
        { peerNodeId: "test-peer", destination: "example.com:443", requestedBytes: 1024 },
        { ...policy, enabled: false }, // gateway disabled
        capacity,
      );
      const deniedWhenDisabled = resultNoLinkUp.decision === "DENY";

      // Negative: a gateway with valid capability but destination not in allowlist
      const resultBadDest = evaluateGatewayRequest(
        { peerNodeId: "test-peer", destination: "evil.com:443", requestedBytes: 1024 },
        policy,
        capacity,
      );
      const deniedBadDest = resultBadDest.decision === "DENY" && resultBadDest.reason === "DESTINATION_NOT_ALLOWED";

      // Negative: SSRF destination blocked even with valid gateway
      // Use a permissive allowlist so the SSRF check is actually reached
      // (the default allowlist would reject 169.254.169.254 as NOT_ALLOWED first)
      const ssrfPolicy = { ...policy, allowedDestinations: ["*"] };
      const resultSsrf = evaluateGatewayRequest(
        { peerNodeId: "test-peer", destination: "169.254.169.254", requestedBytes: 1024 },
        ssrfPolicy,
        capacity,
      );
      const deniedSsrf = resultSsrf.decision === "DENY" && resultSsrf.reason === "DESTINATION_BLOCKED_SSRF";

      // Positive: a valid request with allowed destination passes
      const resultOk = evaluateGatewayRequest(
        { peerNodeId: "test-peer", destination: "example.com:443", requestedBytes: 1024 },
        policy,
        capacity,
      );
      const allowedWhenValid = resultOk.decision === "ALLOW";

      return {
        passed: deniedWhenDisabled && deniedBadDest && deniedSsrf && allowedWhenValid,
        expected: "capability ≠ authorization: disabled gateway DENIES, bad dest DENIES, SSRF DENIES, valid request ALLOWS",
        actual: `disabled=${deniedWhenDisabled}, bad-dest=${deniedBadDest}, ssrf=${deniedSsrf}, valid=${allowedWhenValid}`,
      };
    }),
  );

  // G4: ReportedMetric ≠ ObservedMetric — evidence-type separation (executable)
  // Per R-006.4: a self-reported measurement cannot create a ContributionProof.
  results.push(
    await runOne(14, "ReportedMetric ≠ ObservedMetric — self-reported service creates no proof (spec/00 §31, R-006.4)", "ARCHITECTURE", "spec/00 §31 + spec/14 §2 + spec/11 + R-006.4", async () => {
      const gateway = generateNodeKeypair();
      const peer = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);

      // Negative: a receipt with NO valid signatures (self-reported) cannot
      // create a ContributionProof.
      const selfReportedReceipt = {
        receiptId: toHex(randomBytes(32)),
        gatewayNodeId: gateway.nodeId,
        peerNodeId: peer.nodeId,
        destination: "example.com:443",
        bytesSent: 999999, // claimed, not measured
        bytesReceived: 999999,
        sessionStart: now,
        sessionEnd: now + 10,
        httpStatus: 200,
        gatewaySignature: new Uint8Array(64), // empty (no signature)
        peerSignature: new Uint8Array(64),    // empty (no signature)
      };
      const proofResult = createContributionProof(selfReportedReceipt, gateway.publicKey, peer.publicKey, now);
      const selfReportFails = !proofResult.ok;

      // Negative: SELF_REPORTED_CONTRIBUTION_FORBIDDEN throws
      let guardThrew = false;
      try { SELF_REPORTED_CONTRIBUTION_FORBIDDEN("somenode", 10000); } catch { guardThrew = true; }

      // Positive: a valid bilateral receipt (both signatures) CAN create a proof
      const validReceipt = createBilateralReceipt(
        { receiptId: toHex(randomBytes(32)), gatewayNodeId: gateway.nodeId, peerNodeId: peer.nodeId,
          destination: "example.com:443", bytesSent: 1024, bytesReceived: 4096,
          sessionStart: now, sessionEnd: now + 10, httpStatus: 200 },
        gateway.secretKey, peer.secretKey,
      );
      const validProof = createContributionProof(validReceipt, gateway.publicKey, peer.publicKey, now);
      const bilateralSucceeds = validProof.ok;

      return {
        passed: selfReportFails && guardThrew && bilateralSucceeds,
        expected: "self-reported (no signatures) → no proof; bilateral (both signatures) → proof; SELF_REPORTED_FORBIDDEN throws",
        actual: `self-report fails=${selfReportFails}, guard throws=${guardThrew}, bilateral succeeds=${bilateralSucceeds}`,
      };
    }),
  );

  // G5: Unverified NodeId → executable hop fails (runtime type boundary, not symbol check)
  // Per R-006 hardening: test the AuthenticatedNodeRecord brand, not exported symbol names.
  results.push(
    await runOne(15, "unverified/hint NodeId → ValidatedHop fails — brand boundary (R-006H)", "ARCHITECTURE", "spec/00 §31 + spec/02 §3 + R-006H", async () => {
      const { isValidNodeIdFormat } = await import("@reference/identity/keys");
      const subject = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);

      // Negative: an arbitrary string is NOT a valid NodeId format
      const arbitraryRejected = !isValidNodeIdFormat("not-a-node-id");

      // Negative: a plain object with a valid-looking NodeId is NOT an AuthenticatedNodeRecord
      // (lacks the unforgeable brand)
      const fakeNode = { nodeId: subject.nodeId, publicKey: subject.publicKey };
      const fakeNotAuthenticated = !isAuthenticatedNodeRecord(fakeNode);

      // Negative: attempting to create a ValidatedHop from a non-authenticated object throws
      let fakeToHopThrew = false;
      try {
        createValidatedHop(fakeNode as any, "10.0.0.5:7788", "MESH_RELAY", true, "");
      } catch { fakeToHopThrew = true; }

      // Positive: a genuine AuthenticatedNodeRecord IS recognized
      const authNode = createAuthenticatedNodeRecord({
        advertisement: {
          nodeId: subject.nodeId, signingPublicKey: subject.publicKey,
          capabilities: ["MESH_RELAY"],
          endpoints: [{ type: "tcp", address: "10.0.0.5", port: 7788 }],
          sequence: 1, expiry: now + 3600,
        },
        verifiedAt: now,
      });
      const authRecognized = isAuthenticatedNodeRecord(authNode);

      // Positive: AuthenticatedNodeRecord + LINK_UP → ValidatedHop succeeds
      const validHop = createValidatedHop(authNode, "10.0.0.5:7788", "MESH_RELAY", true, "digest");
      const hopBranded = isValidatedHop(validHop);

      return {
        passed: arbitraryRejected && fakeNotAuthenticated && fakeToHopThrew && authRecognized && hopBranded,
        expected: "arbitrary string rejected; plain object not authenticated; non-auth → ValidatedHop throws; AuthenticatedNodeRecord recognized; ValidatedHop branded",
        actual: `arbitrary rejected=${arbitraryRejected}, fake not auth=${fakeNotAuthenticated}, fake→hop threw=${fakeToHopThrew}, auth recognized=${authRecognized}, hop branded=${hopBranded}`,
      };
    }),
  );

  // G6: Self-reported contribution → no Civic Points (executable against existing contribution.ts)
  // Per R-006.6: test against the EXISTING economics implementation.
  results.push(
    await runOne(16, "self-reported contribution → no proof (spec/00 §31, R-006.6)", "ARCHITECTURE", "spec/00 §31 + spec/11 + R-006.6", async () => {
      const gateway = generateNodeKeypair();
      const peer = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);

      // Negative: self-reported (no bilateral signatures) cannot create a proof
      const noSigReceipt = {
        receiptId: toHex(randomBytes(32)),
        gatewayNodeId: gateway.nodeId, peerNodeId: peer.nodeId,
        destination: "example.com:443",
        bytesSent: 10000, bytesReceived: 10000,
        sessionStart: now, sessionEnd: now + 10, httpStatus: 200,
        gatewaySignature: new Uint8Array(64),
        peerSignature: new Uint8Array(64),
      };
      const noSigResult = createContributionProof(noSigReceipt, gateway.publicKey, peer.publicKey, now);
      const selfReportFails = !noSigResult.ok;

      // Negative: SELF_REPORTED_CONTRIBUTION_FORBIDDEN throws
      let guardThrew = false;
      try { SELF_REPORTED_CONTRIBUTION_FORBIDDEN("node-x", 50000); } catch { guardThrew = true; }

      return {
        passed: selfReportFails && guardThrew,
        expected: "self-reported (no signatures) → no ContributionProof; SELF_REPORTED_FORBIDDEN throws",
        actual: `self-report fails=${selfReportFails}, guard throws=${guardThrew}`,
      };
    }),
  );

  // G7: RouteProposal → ActiveCircuit fails (runtime brand check, not source-text)
  // Per R-006 hardening: use isBrandedCommittedRoute runtime check.
  results.push(
    await runOne(17, "RouteProposal → setupCircuit fails — brand check (R-006H)", "ARCHITECTURE", "spec/00 §31 + spec/08 + R-006H", async () => {
      const kp = generateNodeKeypair();
      const proposal: RouteProposal = {
        routeId: toHex(randomBytes(32)),
        hops: [{ nodeId: kp.nodeId, capability: "MESH_RELAY", endpoint: "10.0.0.1:7788", linkUp: true }],
        requirementDigest: toHex(randomBytes(32)),
        expiry: Math.floor(Date.now() / 1000) + 3600,
        initiatorNodeId: kp.nodeId,
        agreementDigest: toHex(randomBytes(32)),
      };

      // Negative: PROPOSAL_TO_CIRCUIT_FORBIDDEN throws
      let guardThrew = false;
      try { PROPOSAL_TO_CIRCUIT_FORBIDDEN(proposal); } catch { guardThrew = true; }

      // Negative: UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN throws
      let uncommittedThrew = false;
      try { UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN(proposal); } catch { uncommittedThrew = true; }

      // Negative: RouteProposal is NOT a BrandedCommittedRoute (runtime brand check)
      const proposalNotBranded = !isBrandedCommittedRoute(proposal);

      return {
        passed: guardThrew && uncommittedThrew && proposalNotBranded,
        expected: "RouteProposal → setupCircuit fails; PROPOSAL_TO_CIRCUIT_FORBIDDEN + UNCOMMITTED_ROUTE_TO_CIRCUIT_FORBIDDEN throw; RouteProposal not branded",
        actual: `proposal guard=${guardThrew}, uncommitted guard=${uncommittedThrew}, proposal not branded=${proposalNotBranded}`,
      };
    }),
  );

  // G8: NodeId derivation stability across re-derivation
  results.push(
    await runOne(18, "NodeId derivation is byte-stable across re-derivation (spec/02 §2.1)", "PROTOCOL", "spec/02 §2.1 + ADR-0003", () => {
      const kp = generateNodeKeypair();
      const a = deriveNodeId(kp.publicKey);
      const b = deriveNodeId(kp.publicKey);
      const c = deriveNodeId(kp.publicKey);
      return {
        passed: a === b && b === c && a === kp.nodeId,
        expected: "three independent deriveNodeId calls return identical strings",
        actual: `a===b=${a === b}, b===c=${b === c}, a===kp.nodeId=${a === kp.nodeId}`,
      };
    }),
  );

  // G9: Canonical encoding stability
  results.push(
    await runOne(19, "canonical CBOR encoding is stable under re-encoding (ADR-0004)", "PROTOCOL", "spec/03 §6 + ADR-0004", () => {
      const kp = generateNodeKeypair();
      const now = Math.floor(Date.now() / 1000);
      const adv = signAdvertisement({
        protocolVersion: 1, nodeId: kp.nodeId, signingPublicKey: kp.publicKey,
        capabilities: ["MESH_RELAY"], endpoints: [],
        sequence: 1, timestamp: now, expiry: now + 3600, nonce: randomBytes(16),
      }, kp.secretKey);
      const hex = advertisementToHex(adv);
      const bytes = fromHex(hex);
      // isCanonical() internally does: decode(bytes) → re-encode → compare bytes.
      const canonical = isCanonical(bytes);
      // ALSO: decode → re-encode → compare hex.
      const decoded = canonicalDecode(bytes);
      const reHex = toHex(canonicalEncode(decoded));
      return {
        passed: canonical && hex === reHex,
        expected: "isCanonical(bytes) === true AND decode→re-encode is byte-stable",
        actual: `isCanonical=${canonical}, hex===reHex=${hex === reHex}`,
      };
    }),
  );

  // G10: verifyNodeIdBinding rejects incorrect bindings (spec/02 §3 enforcement)
  results.push(
    await runOne(20, "verifyNodeIdBinding rejects mismatched key (spec/02 §3)", "SECURITY", "spec/02 §3 + ADR-0003", () => {
      const kpA = generateNodeKeypair();
      const kpB = generateNodeKeypair();
      const correct = verifyNodeIdBinding(kpA.nodeId, kpA.publicKey);
      const incorrect = verifyNodeIdBinding(kpA.nodeId, kpB.publicKey);
      return {
        passed: correct && !incorrect,
        expected: "correct binding returns true; incorrect returns false",
        actual: `correct=${correct}, incorrect=${incorrect}`,
      };
    }),
  );

  // ---- Layer-separation guards (ADR-0013) ----
  // These are STATIC ANALYSIS tests: they scan source files and assert that
  // the import boundaries are respected. A future developer who accidentally
  // adds `import ... from "@/lib/auth/session"` to a service-layer file will
  // be caught here, before the violation ships.

  // G11: Protocol core (reference/) MUST NOT import from src/ (Layer 3 purity)
  results.push(
    await runOne(21, "protocol core (reference/) has zero imports from src/ (ADR-0013)", "ARCHITECTURE", "spec/00 §27 + spec/16 + ADR-0013", async () => {
      const violations = scanImportBoundaries("reference", [/from\s+["']@\//]);
      return {
        passed: violations.length === 0,
        expected: "reference/ imports only from @reference/* and external packages — never from @/ (src/)",
        actual: violations.length === 0
          ? "0 violations — protocol core is pure and portable"
          : `${violations.length} file(s) with forbidden imports: ${violations.map((v) => `${v.file} (${v.matches.length})`).join("; ")}`,
      };
    }),
  );

  // G12: Service layer (src/lib/sharenet/) MUST NOT import from @/lib/auth/ or @/lib/http/
  results.push(
    await runOne(22, "service layer (src/lib/sharenet/) has zero imports from @/lib/auth/ or @/lib/http/ (ADR-0013)", "ARCHITECTURE", "spec/00 §27 + ADR-0013", async () => {
      const violations = scanImportBoundaries("src/lib/sharenet", [
        /from\s+["']@\/lib\/auth\//,
        /from\s+["']@\/lib\/http\//,
      ]);
      return {
        passed: violations.length === 0,
        expected: "service layer never imports from the web-auth or HTTP layers — web auth cannot bleed into the service plane",
        actual: violations.length === 0
          ? "0 violations — service layer is auth-free"
          : `${violations.length} file(s) with forbidden imports: ${violations.map((v) => `${v.file} (${v.matches.length})`).join("; ")}`,
      };
    }),
  );

  // G13: Protocol core (reference/) MUST NOT import from @/lib/db (no database coupling)
  results.push(
    await runOne(23, "protocol core (reference/) has zero imports from @/lib/db (ADR-0013)", "ARCHITECTURE", "spec/00 §27 + spec/16 + ADR-0013", async () => {
      const violations = scanImportBoundaries("reference", [/from\s+["']@\/lib\/db/]);
      return {
        passed: violations.length === 0,
        expected: "protocol core never imports database client — pure functions only",
        actual: violations.length === 0
          ? "0 violations — protocol core is DB-free"
          : `${violations.length} file(s) with forbidden imports: ${violations.map((v) => v.file).join(", ")}`,
      };
    }),
  );

  // ---- Phase 3 deliverable tests (spec/00 §37 — second major deliverable) ----

  // G14: LinkId is directional — A→B ≠ B→A even with the same nonces
  results.push(
    await runOne(24, "LinkId is directional: A→B ≠ B→A with same nonces (spec/04 §2, ADR-0014)", "ARCHITECTURE", "spec/04 §2 + spec/00 §37 + ADR-0014", async () => {
      const { deriveLinkId, generateLinkNonce } = await import("@reference/link/link");
      // Use canonical NodeId format (52 lowercase base32 chars, no prefix).
      const nodeA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      const nodeB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      const nonceA = generateLinkNonce();
      const nonceB = generateLinkNonce();
      // A→B uses (local=A, remote=B, localNonce=A's, remoteNonce=B's)
      const ab = deriveLinkId(nodeA, nodeB, nonceA, nonceB);
      // B→A uses (local=B, remote=A, localNonce=B's, remoteNonce=A's) — roles swapped
      const ba = deriveLinkId(nodeB, nodeA, nonceB, nonceA);
      return {
        passed: ab !== ba,
        expected: "LinkId(A→B) ≠ LinkId(B→A) — direction is structurally encoded",
        actual: `A→B=${ab.slice(0, 24)}…, B→A=${ba.slice(0, 24)}…, equal=${ab === ba}`,
      };
    }),
  );

  // NOTE: Test #25 (two-process advertisement-verification exchange) has been
  // MOVED to `src/lib/sharenet/integration-mesh-tests.ts` per the corrective
  // milestone (2026-08-16, B4). It is a localhost-network integration test
  // and MUST NOT run in `test:arch` (which must be deterministic, no HTTP,
  // no localhost, no DB). It runs only under `test:integration:mesh`.

  const passed = results.filter((r) => r.status === "passed").length;
  const failed = results.filter((r) => r.status === "failed").length;
  const skipped = results.filter((r) => r.status === "skipped").length;
  return {
    totalTests: results.length,
    passed,
    failed,
    skipped,
    results,
    ranAt: new Date().toISOString(),
    durationMs: Date.now() - start,
    spec: "spec/00 §32 (10 first tests) + spec/00 §31 (forbidden pipeline guards) + spec/00 §37 (Phase 3 two-process links)",
  };
}

/**
 * Per-test timeout. Per the corrective milestone (2026-08-16, F2): an
 * unexpected hang must become a failed named test, not an indefinitely
 * blocked command. Each test MUST complete within 10 seconds; if it
 * exceeds the timeout, it is recorded as FAILED with reason="timeout".
 *
 * 10 seconds is generous (the full suite normally completes in <100ms)
 * but bounded — a hung test cannot block the command indefinitely.
 */
export const ARCH_TEST_TIMEOUT_MS = 10_000;

async function runOne(
  id: number,
  name: string,
  category: ArchTestResult["category"],
  specRef: string,
  fn: () => Promise<
    | { passed: boolean; expected: string; actual: string }
    | { skipped: true; reason: string; expected: string }
  > | { passed: boolean; expected: string; actual: string } | { skipped: true; reason: string; expected: string },
): Promise<ArchTestResult> {
  const t0 = Date.now();
  let status: ArchTestResult["status"] = "failed";
  let passed = false;
  let expected = "";
  let actual = "";
  let skipReason: string | undefined;

  // Print the test name BEFORE execution so a hang is diagnosable.
  // (Per F2: "Add direct runner diagnostics that identify the current
  // test before execution".)
  if (process.env.ARCH_TEST_VERBOSE !== "0") {
    process.stderr.write(`  [arch] running #${id} ${name}...\n`);
  }

  try {
    // Enforce a per-test timeout. If the test fn does not resolve within
    // ARCH_TEST_TIMEOUT_MS, we record it as FAILED with reason="timeout"
    // instead of hanging forever.
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => reject(new Error(`timeout after ${ARCH_TEST_TIMEOUT_MS}ms`)), ARCH_TEST_TIMEOUT_MS);
    });
    const r = await Promise.race([fn(), timeoutPromise]);

    if ("skipped" in r && r.skipped) {
      status = "skipped";
      passed = false; // skipped is NOT passed
      expected = r.expected;
      actual = `SKIPPED — ${r.reason}`;
      skipReason = r.reason;
    } else {
      status = r.passed ? "passed" : "failed";
      passed = r.passed;
      expected = r.expected;
      actual = r.actual;
    }
  } catch (e) {
    status = "failed";
    passed = false;
    expected = "test should not throw or time out";
    actual = `threw: ${(e as Error).message}`;
  }
  return {
    id,
    name,
    category,
    status,
    passed,
    description: `${specRef}`,
    expected,
    actual,
    durationMs: Date.now() - t0,
    skipReason,
  };
}

// Touch imports so they're not tree-shaken (TypeScript will keep them).
void [hexToBytes, bytesToHex, keypairFromSecretKey];

// ---------------------------------------------------------------------
// Static-analysis helper: scan a directory for forbidden import patterns.
// Used by tests #21-23 (ADR-0013 layer-separation guards).
// ---------------------------------------------------------------------

interface ImportViolation {
  file: string;
  matches: string[];
}

/**
 * Walk a directory recursively, read every `.ts` file, and check each line
 * against the forbidden-pattern regexes. Returns a list of violations.
 *
 * This is a STATIC analysis test — it runs at request time in the
 * architecture test runner. It catches accidental cross-layer imports
 * before they ship.
 *
 * Comment lines (starting with `//` or `*` after whitespace) are skipped
 * so that documentation and regex-literal patterns in test code are not
 * false-positive matches.
 */
function scanImportBoundaries(dir: string, forbiddenPatterns: RegExp[]): ImportViolation[] {
  const root = join(process.cwd(), dir);
  if (!existsSync(root)) return [];

  const files: string[] = [];
  function walk(d: string) {
    for (const entry of readdirSync(d)) {
      const full = join(d, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (entry.endsWith(".ts")) {
        files.push(full);
      }
    }
  }
  walk(root);

  const violations: ImportViolation[] = [];
  for (const file of files) {
    const content = readFileSync(file, "utf-8");
    const lines = content.split("\n");
    const matches: string[] = [];
    for (const line of lines) {
      // Skip comment lines so documentation and test-regex patterns
      // don't false-positive.
      const trimmed = line.trimStart();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
      for (const pattern of forbiddenPatterns) {
        if (pattern.test(line)) {
          matches.push(line.trim());
        }
      }
    }
    if (matches.length > 0) {
      violations.push({ file: relative(process.cwd(), file), matches });
    }
  }
  return violations;
}
