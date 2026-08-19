/**
 * ShareNet 2.0 — Circuit key zeroization (R-009 Stage 3).
 *
 * Per spec/08 §6.4 + ADR-0022: when a circuit transitions to CIRCUIT_REVOKED,
 * all derived key material MUST be best-effort zeroized.
 *
 * This module is split out of `forwarding.ts` so that BOTH the canonical
 * teardown path (`processCircuitDestroy` in `destroy.ts`) and the expiry
 * path (`processCircuitWireFrame` in `forwarding.ts`) can call it WITHOUT
 * creating a circular import (`destroy.ts` ↔ `forwarding.ts`). Both modules
 * import `zeroizeCircuit` from here; neither imports the other for this
 * function.
 *
 * NOT guaranteed: the GC may have copied keys; the OS may have paged them.
 * This is defense-in-depth, not a hard memory-erasure guarantee. After
 * zeroize, the circuit object's keys are all zeros — any attempt to use
 * them for AEAD will fail (wrong key → AEAD tag failure).
 */

import type { ActiveCircuit } from "./circuit";

/**
 * Best-effort zeroization of circuit key material, IN-PLACE.
 *
 * Zeroizes:
 *   - each hop's `forwardingKey`
 *   - each hop's `returnKey`
 *   - each hop's `relayX25519PublicKey` (if present)
 *   - `initiatorX25519SecretKey`
 *   - `noncePrefix`
 *
 * NOT zeroized (intentionally retained for revocation + replay lookups
 * after teardown):
 *   - `commitmentRoot` (route identity — needed for replay floor + revocation)
 *   - `circuitId` (circuit identity — needed for revocation checks)
 */
export function zeroizeCircuit(circuit: ActiveCircuit): void {
  for (const hop of circuit.hops) {
    hop.forwardingKey.fill(0);
    hop.returnKey.fill(0);
    if (hop.relayX25519PublicKey) {
      hop.relayX25519PublicKey.fill(0);
    }
  }
  circuit.initiatorX25519SecretKey.fill(0);
  circuit.noncePrefix.fill(0);
  // circuit.commitmentRoot is NOT zeroized — it's the route identity,
  // needed for replay floor lookups + revocation checks.
  // circuit.circuitId is NOT zeroized — it's the circuit identity,
  // needed for revocation checks.
}
