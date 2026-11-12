// The verifier as the site ships it (//verifier, built by TinyGo), asked the
// questions the page asks. What the Go implementations decide is theirs to
// test; these check that the page is given their answers, and the parts of an
// answer that are worked out around them: who signed, the quorum drawn as a
// tree, when it was reached, and the reasons for a refusal.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { b64Encode, type Bytes, hex } from "../web/js/bytes.js";
import { POLICY_SOURCE, POLICY_TEXT } from "../web/js/policy_data.js";
import type { QuorumNode } from "../web/js/verifier.js";
import { siteVerifier } from "../tools/wasm.js";

const file = (f: string) => readFileSync(new URL("testdata/" + f, import.meta.url));
const policy = file("prod-verifier-668ba3c.policy").toString();
const raw = file("checkpoint-5522.txt").toString();
const tile0: Bytes = new Uint8Array(file("tile-0-000.bin"));
const origin = "paic.google.com/log/0";

const verifier = await siteVerifier(new URL("../site/", import.meta.url));
const verify = (checkpoint: string, expected = origin) => verifier.checkpoint(policy, checkpoint, expected);

test("reads the snapshot policy", async () => {
  const p = await verifier.policy(policy);
  assert.deepEqual(p.origins, ["paic.google.com/log/0", "paic.google.com/log/1", "paic.google.com/log/2"]);
  assert.equal(p.logs.length, 5);
  assert.deepEqual([...new Set(p.logs.map((l) => l.alg))].sort(), ["Ed25519", "ML-DSA-44"]);
  assert.equal(p.witnesses.length, 7);
  assert.deepEqual([...new Set(p.witnesses.map((w) => w.alg))].sort(), ["Ed25519 cosignature", "ML-DSA-44"]);
  assert.equal(p.quorum, "cloudflare-geomys-glasklar");
  const log = p.logs[0]!;
  assert.equal(log.name, origin);
  assert.ok(log.vkey.startsWith(`${origin}+${log.keyId.toString(16).padStart(8, "0")}+`));
});

test("the baked-in policy is readable and names its source", async () => {
  const p = await verifier.policy(POLICY_TEXT);
  assert.ok(p.origins.length > 0);
  assert.match(POLICY_SOURCE.commit, /^[0-9a-f]{40}$/);
});

test("malformed policies are refused", async () => {
  const k = "w+00000000+BAAA";
  for (const bad of [`witness a ${k}\n`, "group g any a\nquorum g\n", "frobnicate\nquorum none\n", "quorum nobody\n"]) {
    await assert.rejects(verifier.policy(bad), /the trust policy cannot be read/, bad);
  }
  assert.equal((await verifier.policy("quorum none\n")).quorum, "none");
});

test("a real witnessed checkpoint is accepted, including ML-DSA-44", async () => {
  const r = await verify(raw);
  assert.deepEqual(r.problems, []);
  assert.deepEqual(r.warnings, []);
  assert.ok(r.ok);
  assert.equal(r.checkpoint.origin, origin);
  assert.equal(r.checkpoint.size, 5522);
  assert.equal(hex(r.checkpoint.hash), "e83461decf20833c9b1dd00bdb85ca4f2e5cfbf193db8c3f268d0626c48c8147");
  assert.equal(r.text, raw.slice(0, raw.lastIndexOf("\n\n") + 1));
  assert.equal(r.signatures.length, 9);
  assert.deepEqual([...new Set(r.signatures.map((s) => s.status))], ["valid"]);
  assert.deepEqual(r.signatures.filter((s) => s.role === "log").map((s) => s.algName), ["Ed25519", "ML-DSA-44"]);
  const geomys = r.signatures.find((s) => s.witness === "geomys-golf");
  assert.ok(geomys);
  assert.equal(geomys.algName, "ML-DSA-44");
  assert.equal(new Date(Number(geomys.timestamp) * 1000).toISOString(), "2026-11-11T17:07:22.000Z");
  assert.ok(r.extensionsAuthenticated);
});

test("the quorum is drawn as the policy's tree, with what each part has", async () => {
  const names = (n: QuorumNode): unknown => (n.children ? [n.name, n.satisfied, n.count, n.threshold, n.children.map(names)] : [n.name, n.satisfied]);
  const full = (await verify(raw)).quorum;
  assert.equal(full.kind, "group");
  assert.equal(full.name, "cloudflare-geomys-glasklar");
  assert.ok(full.satisfied);
  assert.equal(full.children?.length, 3);
  assert.equal(full.count, 3);

  // Without Cloudflare, two of the three parts remain.
  const less = (await verify(raw.split("\n").filter((l) => !l.includes("witness.cloudflare.com")).join("\n"))).quorum;
  assert.ok(less.satisfied);
  assert.equal(less.count, 2);
  assert.notDeepEqual(names(less), names(full));
  const find = (n: QuorumNode, name: string): QuorumNode | undefined =>
    n.name === name ? n : (n.children ?? []).map((c) => find(c, name)).find((c) => c !== undefined);
  assert.deepEqual(find(less, "cloudflare-ed25519"), { name: "cloudflare-ed25519", kind: "witness", satisfied: false, count: 0 });
  assert.equal(find(full, "cloudflare-ed25519")?.satisfied, true);

  assert.deepEqual((await verifier.checkpoint("quorum none\n", raw, "")).quorum, { name: "none", kind: "none", satisfied: true, count: 0 });
});

test("a changed tree size invalidates every signature", async () => {
  const r = await verify(raw.replace("\n5522\n", "\n5523\n"));
  assert.ok(!r.ok);
  assert.ok(!r.logSigned);
  assert.ok(!r.quorum.satisfied);
  assert.ok(r.signatures.every((s) => s.status === "invalid"));
  assert.deepEqual(r.problems, ["no valid signature from a log key in the policy", "witness quorum not met"]);
});

test("a checkpoint without enough cosignatures fails the quorum", async () => {
  const r = await verify(raw.split("\n").filter((l) => !/witness\.cloudflare\.com|geomys/.test(l)).join("\n"));
  assert.ok(r.logSigned);
  assert.ok(!r.quorum.satisfied);
  assert.ok(!r.ok);
  assert.equal(r.witnessedAt, null);
  assert.deepEqual(r.problems, ["witness quorum not met"]);
});

test("a checkpoint with only witness signatures is not log-signed", async () => {
  const r = await verify(raw.split("\n").filter((l) => !l.startsWith(`— ${origin} `)).join("\n"));
  assert.ok(r.quorum.satisfied);
  assert.ok(!r.logSigned);
  assert.ok(!r.ok);
});

test("signatures from keys outside the policy are shown and do not count", async () => {
  const stranger = "— example.com/witness " + Buffer.alloc(76, 7).toString("base64") + "\n";
  const r = await verify(raw + stranger);
  assert.ok(r.ok);
  assert.deepEqual(r.signatures.at(-1), { name: "example.com/witness", keyId: 0x07070707, role: "unknown", witness: null, algName: null, status: "unknown-key", timestamp: null });
});

test("an origin outside the policy is rejected", async () => {
  const r = await verify(raw.replace(`${origin}\n5522`, "paic.google.com/log/9\n5522"), "paic.google.com/log/9");
  assert.ok(!r.ok);
  assert.match(r.problems.join(";"), /not a log in the policy/);
});

test("a checkpoint for another log in the policy is not accepted in its place", async () => {
  const r = await verify(raw, "paic.google.com/log/1");
  assert.ok(!r.ok);
  assert.deepEqual(r.problems, ["checkpoint is for paic.google.com/log/0, not paic.google.com/log/1"]);
});

/** Rewrites the signature lines whose key name matches, keeping the rest. */
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
  const r = await verify(editSignature(/^witness\.cloudflare\.com$/, (sig) => { sig[sig.length - 1]! ^= 1; }));
  assert.ok(r.ok);
  assert.ok(r.quorum.satisfied);
  assert.equal(r.signatures.find((s) => s.witness === "cloudflare-ed25519")?.status, "invalid");
  assert.deepEqual(r.warnings, ["invalid signature from witness.cloudflare.com (Ed25519 cosignature)"]);
});

test("a bad signature from one of the log's keys is reported, the other still counts", async () => {
  // The log signs with two keys; break the first line (Ed25519).
  let done = false;
  const r = await verify(editSignature(/^paic\.google\.com\/log\/0$/, (sig) => {
    if (!done) sig[sig.length - 1]! ^= 1;
    done = true;
  }));
  assert.ok(r.ok);
  assert.ok(r.logSigned);
  assert.deepEqual(r.warnings, ["invalid signature from paic.google.com/log/0 (Ed25519)"]);
});

test("what is not a signed checkpoint is refused outright", async () => {
  for (const bad of ["", "not a note", raw.slice(0, raw.lastIndexOf("\n\n") + 1), raw.replace("\n5522\n", "\nmany\n"), raw.replace("\n5522\n", "\n-1\n")]) {
    await assert.rejects(verify(bad), /malformed checkpoint/, JSON.stringify(bad.slice(0, 40)));
  }
  await assert.rejects(verifier.checkpoint("frobnicate\n", raw, origin), /the trust policy cannot be read/);
});

test("extension lines that only ML-DSA signatures vouch for are flagged", async () => {
  // ML-DSA signatures cover origin, size and root hash only, so adding a
  // line leaves them valid while breaking every Ed25519 signature.
  const r = await verify(raw.replace("gUc=\n\n", "gUc=\nsomeone added this\n\n"));
  assert.ok(r.logSigned);
  assert.deepEqual(r.signatures.filter((s) => s.status === "valid").map((s) => s.algName), ["ML-DSA-44", "ML-DSA-44", "ML-DSA-44"]);
  assert.deepEqual(r.checkpoint.extensions, ["someone added this"]);
  assert.ok(!r.extensionsAuthenticated);
  assert.ok(!r.ok); // only Geomys still counts towards the quorum
});

test("the quorum time is when the quorum was reached, not the newest cosignature", async () => {
  // Witnessed at :21 (the staging witness, outside the quorum) and :22.
  const r = await verify(raw);
  assert.equal(r.witnessedAt, 1794416842n);
  assert.equal(new Date(Number(r.witnessedAt) * 1000).toISOString(), "2026-11-11T17:07:22.000Z");
});

// Tree heads of the first n leaves of paic.google.com/log/0.
const ROOTS = [
  "a42a259c56497e0a2ad88f13623e472ce4e1a53ec899228b20cee1781bb4f245",
  "455085e46707c789a0c7cf7b66f47f8fe8fb21a137cd87fe9dbb56e4e7ffdcc3",
  "6d90a74990d105847ac93bd385d7d88635337d31765ca6ae9f7e0f5836823d3b",
  "08505184983a190fa73bf7505a88d34d509d1278104e2fe5032cc9de3735db97",
  "46d41510beb90a6208596c4ccb72d81cb1c4e200f8ddcbf2ca98c6bae5638f28",
  "a1fccabd120189dba49ae0bc24dadc6ff2bc1d2f02c5c08f39a4d5c7bf607bce",
  "4885b292c815ead602c7a85d905f2910394b2bd3e8695bc0ea79e8dd60a4fc79",
];
const level1 = hex(new Uint8Array(file("tile-1-000-first-hash.bin")));

test("tree heads", async () => {
  assert.equal(hex((await verifier.tree(new Uint8Array(0), 0)).root), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  for (let n = 1; n <= ROOTS.length; n++) {
    assert.equal(hex((await verifier.tree(tile0, n)).root), ROOTS[n - 1], `size ${n}`);
  }
  // The first hash of the log's level-1 tile is the head of the first 256 leaves.
  assert.equal(hex((await verifier.tree(tile0, 256)).root), level1);
  await assert.rejects(verifier.tree(tile0, 257), /could not hash the tree/);
});

test("the tiles a log of a given size must serve above level 0", async () => {
  const shape = async (leaves: Bytes, size: number) =>
    (await verifier.tree(leaves, size)).interior.map((t) => `${t.level}/${t.index} x${t.width}`);
  // 255 leaves: no complete group, so no interior tiles.
  assert.deepEqual(await shape(tile0, 255), []);
  // 256 real leaves: one level-1 hash, as the log itself serves it.
  const one = (await verifier.tree(tile0, 256)).interior;
  assert.deepEqual(one.map((t) => ({ ...t, data: hex(t.data) })), [{ level: 1, index: 0, width: 1, data: level1, path: "tile/1/000.p/1" }]);
  // 600 leaves: two complete groups; the 88 left over belong to no tile hash.
  const leaves = new Uint8Array(600 * 32);
  for (let i = 0; i < leaves.length; i++) leaves[i] = (i * 7) & 0xff;
  const [two, ...none] = (await verifier.tree(leaves, 600)).interior;
  assert.deepEqual(none, []);
  assert.equal(two?.width, 2);
  assert.equal(hex(two!.data), hex((await verifier.tree(leaves, 256)).root) + hex((await verifier.tree(leaves.subarray(8192), 256)).root));
  // 65,536 leaves fill a level-2 hash, which is the head of the whole tree.
  const big = new Uint8Array(65536 * 32);
  for (let i = 0; i < big.length; i += 32) new DataView(big.buffer).setUint32(i, i);
  const full = await verifier.tree(big, 65536);
  assert.deepEqual(full.interior.map((t) => `${t.level}/${t.index} x${t.width}`).sort(), ["1/0 x256", "2/0 x1"]);
  assert.equal(hex(full.interior.find((t) => t.level === 2)!.data), hex(full.root));
});

// Inclusion proofs in the first leaves of paic.google.com/log/0: size, leaf, tree head, proof.
const PROOFS: [number, number, string, string[]][] = [
  [1, 0, ROOTS[0]!, []],
  [200, 199, "b7d906943e0b5273343eb39a3015c6471cd62f423567116f1eddef434b2f94c8", ["9a63e139862be6fce1fedc6e5c03a1f74014fef3e4526105f50dd938b8f6bb83", "c27999fc4fe13a35f07fc072daf33920354cd7e5dc6aab454ea33b2d566d4bbc", "3d06c15acffe6a44bf15b34ab8558017e67e0935988aeb2263e6a818d7dbac64", "2d9cbbdaf000ae0d38dddbd480f9de735cc88fda7921c7b24a929261957f4893", "b21917fa459507660e8db70940835680e01266aa6cdcc108bc788042a3d34919"]],
  [201, 100, "62746dab65a01eaedf052d42cbeb16a770e57793c257155cbf39aa1bd2c0b98c", ["4ca2c8b24dd367106df70e7ab5d30a895cfca63175bda60881c06e71d9cc021c", "dc9cc5ee9b9bca8277f748c400e0ebe50d24af4283388171b1d21609e7e32240", "8590f24a0f30ae23cf0b878fcbda6a98e03edc19002021522fe1e1083c7803f6", "958b06ca57e7e620358a4a33be8ae6d4332564d97e8e3d9936d8ba0a706a70d8", "62ca0dac855f7a7329ccc85cebc490a6de311744efad537624132832c308b98b", "a87a1c4d6c298a5e76664b1c1028f0fbef5ab9227e4c9762ce2d6e9725b9799c", "3a8440cdd1ea7a139cb0025f71fedb51a1a68cfb0f28a18abae958079d989303", "d2a090c55d10348e697b55e514d174adef60f3801ad68777f3bbbc7a4d1234b6"]],
  [256, 255, "87dfb42cbab17c1658d776218231794b72a4e7ff99fc843f3d6d9837aa1ba5c0", ["e202264d253fb4ed7cd1c014d1e31859651b31683cc84664f270293f2eacca5a", "9ec9b6f3dd6852baf673047c275642e467faa4468f18e6b041a0ece75e1be046", "a0577f29537c9c9ecbbc6040a95b2c45a0283b27567b6bb43fea4e69a58c5597", "ab6c2977877f4f8bf0cf9a330fc2fb0d573c785555c88cb4a7c2a2c8c612c3e4", "24687021d1335efb296c8c18aa7cd20104f28fde1eafed918dc4f3f90d1ed47e", "09e26429dd59a065a989c6da35f2673e2fa351334aa7c41923519bc185a57453", "2d9cbbdaf000ae0d38dddbd480f9de735cc88fda7921c7b24a929261957f4893", "b21917fa459507660e8db70940835680e01266aa6cdcc108bc788042a3d34919"]],
];

test("proofs are written in the c2sp.org/tlog-proof form", async () => {
  const checkpoint = "example.com/log\n7\nAAAA\n\n— example.com/log AAAAAAAA\n";
  for (const [size, index, root, want] of PROOFS) {
    assert.equal(hex((await verifier.tree(tile0, size)).root), root);
    assert.equal(await verifier.prove(tile0, size, index, checkpoint), [
      "c2sp.org/tlog-proof@v1",
      `index ${index}`,
      ...want.map((h) => b64Encode(Uint8Array.from(Buffer.from(h, "hex")))),
      "",
      checkpoint,
    ].join("\n"), `size ${size}, leaf ${index}`);
  }
  await assert.rejects(verifier.prove(tile0, 201, 201, checkpoint), /could not write the proof/);
});
