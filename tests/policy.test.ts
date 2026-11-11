import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { evaluateQuorum, logOrigins, parsePolicy } from "../web/js/policy.js";
import { POLICY_SOURCE, POLICY_TEXT } from "../web/js/policy_data.js";

const snapshot = readFileSync(new URL("testdata/prod-verifier-668ba3c.policy", import.meta.url), "utf8");

test("parses the snapshot policy", () => {
  const p = parsePolicy(snapshot);
  assert.deepEqual(logOrigins(p), ["paic.google.com/log/0", "paic.google.com/log/1", "paic.google.com/log/2"]);
  assert.equal(p.logs.length, 5);
  assert.equal(p.witnesses.length, 7);
  assert.equal(p.quorum, "cloudflare-geomys-glasklar");
});

test("the baked-in policy parses and names its source", () => {
  const p = parsePolicy(POLICY_TEXT);
  assert.ok(logOrigins(p).length > 0);
  assert.match(POLICY_SOURCE.commit, /^[0-9a-f]{40}$/);
  // Whatever the quorum is, it must be reachable when every witness signs.
  assert.ok(evaluateQuorum(p, new Set(p.witnesses.map((w) => w.name))).satisfied);
});

test("quorum evaluation follows nested thresholds", () => {
  const p = parsePolicy(snapshot);
  const sat = (...names: string[]) => evaluateQuorum(p, new Set(names)).satisfied;
  assert.ok(sat("cloudflare-ed25519", "geomys-golf"));
  assert.ok(sat("cloudflare-ed25519", "glasklar-g1-02-ed25519"));
  assert.ok(!sat("cloudflare-ed25519"));
  assert.ok(!sat("glasklar-g1-01-ed25519", "glasklar-g1-02-ed25519", "glasklar-g1-03-ed25519"));
  assert.ok(!sat("tf-ed25519", "tf-mldsa44", "geomys-golf"));
});

test("rejects malformed policies", () => {
  const k = "w+00000000+BAAA";
  assert.throws(() => parsePolicy(`witness a ${k}\n`), /no quorum/);
  assert.throws(() => parsePolicy(`group g any a\nquorum g\n`), /undefined/);
  assert.throws(() => parsePolicy(`witness a ${k}\ngroup g 2 a\nquorum g\n`), /threshold/);
  assert.throws(() => parsePolicy(`witness a ${k}\nwitness a ${k}\nquorum a\n`), /duplicate/);
  assert.throws(() => parsePolicy(`witness a w+00000000+AQAA\nquorum a\n`), /cosignature/);
  assert.throws(() => parsePolicy(`frobnicate\nquorum none\n`), /unknown keyword/);
});
