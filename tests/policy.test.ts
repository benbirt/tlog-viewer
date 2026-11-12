import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { newVerifier } from "../web/js/note.js";
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

test("every key in the baked-in policy is usable", async () => {
  const p = parsePolicy(POLICY_TEXT);
  // newVerifier checks each key's length and that its ID matches its bytes.
  for (const { vkey } of [...p.logs, ...p.witnesses]) {
    assert.ok((await newVerifier(vkey)).supported, vkey.name);
  }
});

test("comments may be indented, and need no space after the #", () => {
  const p = parsePolicy(`  # indented\n\t#tabbed\n#plain\n\nquorum none\n`);
  assert.equal(p.quorum, "none");
});

test("rejects duplicate public keys and control characters", () => {
  const key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  // The same key bytes under two names, as a witness and as a log.
  assert.throws(() => parsePolicy(`witness a w1+00000000+B${key.slice(1)}\nwitness b w2+11111111+B${key.slice(1)}\nquorum a\n`), /duplicate witness public key/);
  assert.throws(() => parsePolicy(`log l1+00000000+A${key.slice(1)}\nlog l2+11111111+A${key.slice(1)}\nquorum none\n`), /duplicate log public key/);
  assert.throws(() => parsePolicy(`quorum none\r\n`), /control character/);
});

test("groups form a tree, thresholds are plain numbers, and URLs are absolute", () => {
  const a = "witness a w+00000000+BAAA";
  const b = "witness b x+00000000+BAAB";
  // A name may be a member of only one group in the whole policy.
  assert.throws(() => parsePolicy(`${a}\ngroup g any a\ngroup h any a\nquorum h\n`), /member of more than one group/);
  assert.throws(() => parsePolicy(`${a}\n${b}\ngroup g any a b\ngroup h all g b\nquorum h\n`), /member of more than one group/);
  assert.throws(() => parsePolicy(`${a}\ngroup g any a a\nquorum g\n`), /member of more than one group/);
  assert.equal(parsePolicy(`${a}\n${b}\ngroup g any a\ngroup h all g b\nquorum h\n`).groups.length, 2);
  // Thresholds are read as Go reads them: leading zeros allowed, within 1 to the group's size.
  assert.equal(parsePolicy(`${a}\ngroup g 01 a\nquorum g\n`).groups[0]?.threshold, 1);
  for (const bad of ["0", "2", "-1", "+1", "1.0", "one", "99999999999"]) {
    assert.throws(() => parsePolicy(`${a}\ngroup g ${bad} a\nquorum g\n`), /threshold/, bad);
  }
  assert.equal(parsePolicy(`${a} https://witness.example/path\nquorum a\n`).witnesses[0]?.url, "https://witness.example/path");
  for (const bad of ["witness.example", "/relative", "ftp://witness.example", "https://example.com/%zz", "http://[::1"]) {
    assert.throws(() => parsePolicy(`${a} ${bad}\nquorum a\n`), /not an absolute http\(s\) URL/, bad);
  }
});
