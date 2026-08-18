import { deriveNoncePrefix } from "@reference/circuit/circuit";
import { x25519 } from "@noble/curves/ed25519.js";

const commitmentRootHex = "5eda2d028c04622ab972ec6f800dcffb5a6ab9a2f7095e0e832b2922db32d8b9";
const commitmentRoot = new Uint8Array(commitmentRootHex.match(/.{2}/g)!.map(h => parseInt(h, 16)));

// Use a FIXED initiator ephemeral key (deterministic for the frozen vector).
const initSk = new Uint8Array(32).fill(0x01);
const initPk = x25519.getPublicKey(initSk);
const initPkHex = Array.from(initPk).map(b => b.toString(16).padStart(2, "0")).join("");

const np = deriveNoncePrefix(commitmentRoot, initPk);
const npHex = Array.from(np).map(b => b.toString(16).padStart(2, "0")).join("");

// Also compute a SECOND nonce prefix with a DIFFERENT ephemeral key to prove re-key freshness.
const initSk2 = new Uint8Array(32).fill(0x02);
const initPk2 = x25519.getPublicKey(initSk2);
const initPk2Hex = Array.from(initPk2).map(b => b.toString(16).padStart(2, "0")).join("");
const np2 = deriveNoncePrefix(commitmentRoot, initPk2);
const np2Hex = Array.from(np2).map(b => b.toString(16).padStart(2, "0")).join("");

console.log(JSON.stringify({
  initPkHex,
  noncePrefixHex: npHex,
  initPk2Hex,
  noncePrefix2Hex: np2Hex,
  different: npHex !== np2Hex,
}, null, 2));
