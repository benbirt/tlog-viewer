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
  assert.ok(geomys.timestamp !== null);
  assert.equal(new Date(geomys.timestamp * 1000).toISOString(), "2026-11-11T17:07:22.000Z");
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
