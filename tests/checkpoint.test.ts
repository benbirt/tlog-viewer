import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { hex } from "../web/js/bytes.js";
import { verifyCheckpoint } from "../web/js/note.js";
import { parsePolicy } from "../web/js/policy.js";

const read = (f: string) => readFileSync(new URL("testdata/" + f, import.meta.url), "utf8");
const policy = parsePolicy(read("prod-verifier-668ba3c.policy"));
const raw = read("checkpoint-5522.txt");

test("verifies a real witnessed checkpoint, including ML-DSA-44", async () => {
  const r = await verifyCheckpoint(policy, raw);
  assert.deepEqual(r.problems, []);
  assert.ok(r.ok);
  assert.equal(r.checkpoint.origin, "paic.google.com/log/0");
  assert.equal(r.checkpoint.size, 5522);
  assert.equal(hex(r.checkpoint.hash), "e83461decf20833c9b1dd00bdb85ca4f2e5cfbf193db8c3f268d0626c48c8147");
  assert.equal(r.signatures.length, 9);
  assert.deepEqual([...new Set(r.signatures.map((s) => s.status))], ["valid"]);
  assert.deepEqual(r.signatures.filter((s) => s.role === "log").map((s) => s.algName), ["Ed25519", "ML-DSA-44"]);
  const geomys = r.signatures.find((s) => s.witness === "geomys-golf");
  assert.ok(geomys);
  assert.equal(geomys.algName, "ML-DSA-44");
  assert.equal(typeof geomys.timestamp, "bigint");
  assert.equal(new Date(Number(geomys.timestamp) * 1000).toISOString(), "2026-11-11T17:07:22.000Z");
});

test("a changed tree size invalidates every signature", async () => {
  const r = await verifyCheckpoint(policy, raw.replace("\n5522\n", "\n5523\n"));
  assert.ok(!r.ok);
  assert.ok(!r.logSigned);
  assert.ok(!r.quorum.satisfied);
  assert.ok(r.signatures.every((s) => s.status === "invalid"));
});

test("a checkpoint without enough cosignatures fails the quorum", async () => {
  const lines = raw.split("\n").filter((l) => !/witness\.cloudflare\.com|geomys/.test(l));
  const r = await verifyCheckpoint(policy, lines.join("\n"));
  assert.ok(r.logSigned);
  assert.ok(!r.quorum.satisfied);
  assert.ok(!r.ok);
});

test("a checkpoint with only witness signatures is not log-signed", async () => {
  const lines = raw.split("\n").filter((l) => !l.startsWith("— paic.google.com/log/0 "));
  const r = await verifyCheckpoint(policy, lines.join("\n"));
  assert.ok(r.quorum.satisfied);
  assert.ok(!r.logSigned);
  assert.ok(!r.ok);
});

test("signatures from keys outside the policy are ignored", async () => {
  const stranger = "— example.com/witness " + Buffer.alloc(76, 7).toString("base64") + "\n";
  const r = await verifyCheckpoint(policy, raw + stranger);
  assert.ok(r.ok);
  assert.equal(r.signatures.at(-1)?.status, "unknown-key");
});

test("an origin outside the policy is rejected", async () => {
  const r = await verifyCheckpoint(policy, raw.replace("paic.google.com/log/0\n5522", "paic.google.com/log/9\n5522"));
  assert.ok(!r.ok);
  assert.match(r.problems.join(";"), /not a log in the policy/);
});

/** Rewrites the signature line whose key name matches, keeping the rest. */
function editSignature(name: RegExp, edit: (sig: Buffer) => void): string {
  return raw.split("\n").map((line) => {
    const m = /^— (\S+) (\S+)$/.exec(line);
    if (!m || !name.test(m[1]!)) return line;
    const sig = Buffer.from(m[2]!, "base64");
    edit(sig);
    return `— ${m[1]} ${sig.toString("base64")}`;
  }).join("\n");
}

test("one bad cosignature does not reject a checkpoint the others make valid", async () => {
  // Corrupt Cloudflare's signature; Geomys and Glasklar still make 2 of 3.
  const r = await verifyCheckpoint(policy, editSignature(/^witness\.cloudflare\.com$/, (sig) => { sig[sig.length - 1]! ^= 1; }));
  assert.ok(r.ok);
  assert.ok(r.quorum.satisfied);
  assert.equal(r.signatures.find((s) => s.witness === "cloudflare-ed25519")?.status, "invalid");
  assert.deepEqual(r.warnings, ["invalid signature from witness.cloudflare.com (Ed25519 cosignature)"]);
});

test("a bad signature from one of the log's keys is reported, the other still counts", async () => {
  // The log signs with two keys; break the first line (Ed25519).
  let done = false;
  const r = await verifyCheckpoint(policy, editSignature(/^paic\.google\.com\/log\/0$/, (sig) => {
    if (!done) sig[sig.length - 1]! ^= 1;
    done = true;
  }));
  assert.ok(r.ok);
  assert.ok(r.logSigned);
  assert.deepEqual(r.warnings, ["invalid signature from paic.google.com/log/0 (Ed25519)"]);
});

test("two signature lines from the same key reject the checkpoint", async () => {
  const cloudflare = raw.split("\n").find((l) => l.includes("witness.cloudflare.com"))!;
  const r = await verifyCheckpoint(policy, raw + cloudflare + "\n");
  assert.ok(!r.ok);
  assert.match(r.problems.join(";"), /more than one signature line from witness\.cloudflare\.com/);

  const stranger = "— example.com/witness " + Buffer.alloc(76, 7).toString("base64") + "\n";
  const r2 = await verifyCheckpoint(policy, raw + stranger + stranger);
  assert.ok(!r2.ok);
});

test("a checkpoint for another log in the policy is not accepted in its place", async () => {
  assert.ok((await verifyCheckpoint(policy, raw, "paic.google.com/log/0")).ok);
  const r = await verifyCheckpoint(policy, raw, "paic.google.com/log/1");
  assert.ok(!r.ok);
  assert.match(r.problems.join(";"), /checkpoint is for paic\.google\.com\/log\/0, not paic\.google\.com\/log\/1/);
});

test("malformed checkpoints are refused outright", async () => {
  const hashLine = "6DRh3s8ggzybHdAL24XKTy5c+/GT24w/Jo0GJsSMgUc=\n";
  assert.ok(raw.includes(hashLine));
  // An empty extension line.
  await assert.rejects(verifyCheckpoint(policy, raw.replace(hashLine, hashLine + "\nextension\n")), /bad extension line/);
  // The same root hash, encoded with a stray bit in the last character.
  await assert.rejects(verifyCheckpoint(policy, raw.replace(hashLine, hashLine.replace("Uc=", "Ud="))), /non-canonical base64/);
  // A "+" in a signer's name.
  await assert.rejects(verifyCheckpoint(policy, raw + "— a+b " + Buffer.alloc(76, 7).toString("base64") + "\n"), /bad signature line/);
});

test("extension lines that only ML-DSA signatures vouch for are flagged", async () => {
  assert.ok((await verifyCheckpoint(policy, raw)).extensionsAuthenticated);
  // ML-DSA cosignatures cover origin, size and root hash only, so adding a
  // line leaves them valid while breaking every Ed25519 signature.
  const r = await verifyCheckpoint(policy, raw.replace("gUc=\n\n", "gUc=\nsomeone added this\n\n"));
  assert.ok(r.logSigned);
  assert.deepEqual(r.signatures.filter((s) => s.status === "valid").map((s) => s.algName), ["ML-DSA-44", "ML-DSA-44", "ML-DSA-44"]);
  assert.deepEqual(r.checkpoint.extensions, ["someone added this"]);
  assert.ok(!r.extensionsAuthenticated);
  assert.ok(!r.ok); // only Geomys still counts towards the quorum
});
