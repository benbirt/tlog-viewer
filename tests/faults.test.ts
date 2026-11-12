import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import type { Bytes } from "../web/js/bytes.js";
import { decodeEntry } from "../web/js/entry.js";
import { type Fault, faultById, FAULTS, faultTargets, faultyFetch } from "../web/js/faults.js";
import { leafHash } from "../web/js/ingest.js";
import { LogClient, parseBundle } from "../web/js/tiles.js";
import { siteVerifier } from "../tools/wasm.js";

const file = (f: string) => readFileSync(new URL("testdata/" + f, import.meta.url));
const policy = file("prod-verifier-668ba3c.policy").toString();
const verifier = await siteVerifier(new URL("../site/", import.meta.url));
const raw = file("checkpoint-5522.txt").toString();
const bundle: Bytes = new Uint8Array(file("entries-first7.bin"));
const tile0: Bytes = new Uint8Array(file("tile-0-000.bin"));

const fault = (id: string): Fault => {
  const f = faultById(id);
  assert.ok(f, id);
  return f;
};
const origin = "paic.google.com/log/0";

test("fault ids are unique and each fault does something", () => {
  assert.equal(new Set(FAULTS.map((f) => f.id)).size, FAULTS.length);
  for (const f of FAULTS) {
    assert.ok(f.checkpoint || f.checkpointFromOtherLog || f.tile || f.entry || f.clockOffsetMs, f.id);
    assert.equal(f.entry !== undefined, f.entryStage !== undefined, f.id);
  }
  assert.equal(faultById("no-such-fault"), null);
  assert.equal(faultById(null), null);
  assert.deepEqual(faultTargets(10), [9, 7]);
  assert.deepEqual(faultTargets(1), [0]);
  assert.deepEqual(faultTargets(0), []);
});

test("checkpoint faults produce the failures they describe", async () => {
  const verify = (id: string) => verifier.checkpoint(policy, fault(id).checkpoint!(raw), origin);

  const logSig = await verify("log-signature");
  assert.ok(!logSig.ok && !logSig.logSigned && logSig.quorum.satisfied);

  const oneLogSig = await verify("one-log-signature");
  assert.ok(oneLogSig.ok && oneLogSig.logSigned);
  assert.equal(oneLogSig.warnings.length, 1);

  const witness = await verify("witness-signature");
  assert.ok(witness.ok);
  assert.equal(witness.warnings.length, 1);
  assert.match(witness.warnings[0]!, /cosignature/);

  const noQuorum = await verify("no-quorum");
  assert.ok(!noQuorum.ok && noQuorum.logSigned && !noQuorum.quorum.satisfied);
  assert.equal(noQuorum.signatures.filter((s) => s.role === "witness").length, 1);
});

test("tile faults are applied by the fetch wrapper", async () => {
  const served: Record<string, Bytes | string> = {
    "https://log.example/checkpoint": raw,
    "https://log.example/tile/0/000": tile0,
    "https://log.example/tile/entries/000.p/7": bundle,
  };
  const inner = async (url: string) => (served[url] !== undefined ? new Response(served[url]) : new Response("no", { status: 404 }));
  const client = (id: string) => new LogClient("https://log.example/", faultyFetch(fault(id), "https://log.example/", inner));

  const altered = await client("leaf-hashes").hashTile({ index: 0, width: 256 });
  assert.equal(altered[0], tile0[0]! ^ 1);
  assert.deepEqual(altered.subarray(1), tile0.subarray(1));

  await assert.rejects(client("tile-unavailable").entryBundle({ index: 0, width: 7 }), /HTTP 503/);
  assert.equal((await client("tile-unavailable").hashTile({ index: 0, width: 256 }))[0], tile0[0]);
  assert.notEqual(await client("log-signature").checkpoint(), raw);
  assert.equal(await client("leaf-hashes").checkpoint(), raw);
});

test("entry faults produce the failures they describe", async () => {
  const entry = parseBundle(bundle)[0]!;
  const decode = (id: string) => decodeEntry(fault(id).entry!(entry));

  assert.deepEqual((await decode("entry-signature")).checks, { contentHash: true, signature: false });
  assert.deepEqual((await decode("entry-content")).checks, { contentHash: false, signature: false });
  assert.equal((await decode("entry-content")).summary?.subjectName, "altered-mpm_d62bab1c86");

  const key = await decode("entry-key");
  assert.deepEqual(key.checks, { contentHash: true, signature: false });
  assert.ok(key.keyError && key.summary);

  assert.ok((await decode("entry-garbage")).error);

  // The "served" fault leaves the entry itself intact but changes its leaf hash.
  const swapped = fault("entry-swapped").entry!(entry);
  assert.deepEqual((await decodeEntry(swapped)).checks, { contentHash: true, signature: true });
  assert.notDeepEqual(await leafHash(swapped), await leafHash(entry));
});
