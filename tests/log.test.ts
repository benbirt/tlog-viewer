import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { type Bytes, hex } from "../web/js/bytes.js";
import { decodeEntry, derSignatureToRaw, statementTextOf } from "../web/js/entry.js";
import { checkBundle, hashTree } from "../web/js/ingest.js";
import { verifyInteriorTiles } from "../web/js/interior.js";
import { inclusionProof, interiorTileHashes, leafHash, rootFromInclusionProof, rootFromLeafHashes } from "../web/js/merkle.js";
import { formatTlogProof, parseTlogProof } from "../web/js/proof.js";
import { encodeIndex, HttpError, LogClient, parseBundle, tilePath, tilesForSize } from "../web/js/tiles.js";

const read = (f: string): Bytes => new Uint8Array(readFileSync(new URL("testdata/" + f, import.meta.url)));
const bytes = (s: string): Bytes => new Uint8Array(Buffer.from(s));
const bundle = read("entries-first7.bin");
const tile0 = read("tile-0-000.bin");

// Tree heads of the first n leaves of paic.google.com/log/0, computed with
// golang.org/x/mod/sumdb/tlog.
const ROOTS = [
  "a42a259c56497e0a2ad88f13623e472ce4e1a53ec899228b20cee1781bb4f245",
  "455085e46707c789a0c7cf7b66f47f8fe8fb21a137cd87fe9dbb56e4e7ffdcc3",
  "6d90a74990d105847ac93bd385d7d88635337d31765ca6ae9f7e0f5836823d3b",
  "08505184983a190fa73bf7505a88d34d509d1278104e2fe5032cc9de3735db97",
  "46d41510beb90a6208596c4ccb72d81cb1c4e200f8ddcbf2ca98c6bae5638f28",
  "a1fccabd120189dba49ae0bc24dadc6ff2bc1d2f02c5c08f39a4d5c7bf607bce",
  "4885b292c815ead602c7a85d905f2910394b2bd3e8695bc0ea79e8dd60a4fc79",
];

test("tile paths", () => {
  assert.equal(encodeIndex(0), "000");
  assert.equal(encodeIndex(1234067), "x001/x234/067");
  assert.equal(tilePath(0, 21, 146), "tile/0/021.p/146");
  assert.equal(tilePath("entries", 1000), "tile/entries/x001/000");
  assert.deepEqual(tilesForSize(0), []);
  assert.deepEqual(tilesForSize(256), [{ index: 0, width: 256 }]);
  assert.deepEqual(tilesForSize(258), [{ index: 0, width: 256 }, { index: 1, width: 2 }]);
});

test("entry leaf hashes match the log's level-0 tile", async () => {
  const entries = parseBundle(bundle);
  assert.equal(entries.length, 7);
  for (let i = 0; i < entries.length; i++) {
    assert.equal(hex(await leafHash(entries[i]!)), hex(tile0.subarray(i * 32, i * 32 + 32)));
  }
});

test("Merkle tree heads", async () => {
  assert.equal(hex(await rootFromLeafHashes(new Uint8Array(0))), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  for (let n = 1; n <= ROOTS.length; n++) {
    assert.equal(hex(await rootFromLeafHashes(tile0, n)), ROOTS[n - 1], `size ${n}`);
  }
  // The first hash of the level-1 tile is the head of the first 256 leaves.
  assert.equal(hex(await rootFromLeafHashes(tile0)), hex(read("tile-1-000-first-hash.bin")));
});

test("interior tile hashes", async () => {
  // 255 leaves: no complete group, so no interior tiles.
  assert.deepEqual(await interiorTileHashes(tile0, 255), []);
  // 256 real leaves: one level-1 hash, as the log itself serves it.
  const one = await interiorTileHashes(tile0);
  assert.equal(one.length, 1);
  assert.equal(hex(one[0]!), hex(read("tile-1-000-first-hash.bin")));
  // 600 leaves: two complete groups; the 88 left over belong to no tile hash.
  const leaves = new Uint8Array(600 * 32);
  for (let i = 0; i < leaves.length; i++) leaves[i] = (i * 7) & 0xff;
  const two = await interiorTileHashes(leaves);
  assert.equal(two.length, 1);
  assert.equal(hex(two[0]!), hex(await rootFromLeafHashes(leaves, 256)) + hex(await rootFromLeafHashes(leaves.subarray(8192), 256)));
  // 65,536 leaves fill a level-2 hash, which is the head of the whole tree.
  const big = new Uint8Array(65536 * 32);
  for (let i = 0; i < big.length; i += 32) new DataView(big.buffer).setUint32(i, i);
  const levels = await interiorTileHashes(big);
  assert.deepEqual(levels.map((l) => l.length / 32), [256, 1]);
  assert.equal(hex(levels[1]!), hex(await rootFromLeafHashes(big)));
});

test("interior tiles are checked against the leaves", async () => {
  // A log of 600 leaves has one partial level-1 tile holding two hashes.
  const leaves = new Uint8Array(600 * 32);
  for (let i = 0; i < leaves.length; i++) leaves[i] = (i * 7) & 0xff;
  const [tile] = await interiorTileHashes(leaves);
  assert.ok(tile);
  const serve = (body: Bytes) => new LogClient("https://log.example/", async (url) =>
    url === "https://log.example/tile/1/000.p/2" ? new Response(body) : new Response("no", { status: 404 }));

  assert.deepEqual(await verifyInteriorTiles(serve(tile), leaves, 600), { checked: 1, mismatched: [] });

  const corrupt = tile.slice();
  corrupt[40]! ^= 1;
  assert.deepEqual(await verifyInteriorTiles(serve(corrupt), leaves, 600), { checked: 1, mismatched: ["tile/1/000.p/2"] });

  // Too small for interior tiles: nothing is fetched.
  assert.deepEqual(await verifyInteriorTiles(serve(tile), leaves, 255), { checked: 0, mismatched: [] });
  // A missing tile is an error, not a pass.
  await assert.rejects(verifyInteriorTiles(serve(tile), leaves.subarray(0, 300 * 32), 300), (e) => e instanceof HttpError);
});

test("truncated bundles are rejected", () => {
  assert.throws(() => parseBundle(bundle.subarray(0, bundle.length - 1)), /truncated/);
  assert.throws(() => parseBundle(Uint8Array.of(0)), /truncated/);
});

test("LogClient checks tile sizes and reports HTTP errors", async () => {
  const served: Record<string, Bytes> = { "https://log.example/tile/entries/000.p/7": bundle, "https://log.example/tile/0/000": tile0 };
  const client = new LogClient("https://log.example/", async (url) =>
    served[url] ? new Response(served[url]) : new Response("no", { status: 404 }));
  assert.equal((await client.entryBundle({ index: 0, width: 7 })).length, 7);
  assert.equal((await client.hashTile({ index: 0, width: 256 })).length, 8192);
  await assert.rejects(client.hashTile({ index: 0, width: 256 }, 1), (e) => e instanceof HttpError && e.url.endsWith("/tile/1/000"));
  await assert.rejects(client.hashTile({ index: 1, width: 3 }), (e) => e instanceof HttpError && e.status === 404);
});

test("decodes and verifies real endorsement entries", async () => {
  for (const bytes of parseBundle(bundle)) {
    const e = await decodeEntry(bytes);
    assert.equal(e.error, null);
    assert.deepEqual(e.checks, { contentHash: true, signature: true });
    assert.equal(e.summary?.predicateType, "https://project-oak.github.io/oak/tr/endorsement/v1");
    assert.match(e.keyFingerprint ?? "", /^[0-9a-f]{64}$/);
  }
  const first = await decodeEntry(parseBundle(bundle)[0]!);
  assert.equal(first.summary?.subjectName, "mpm_d62bab1c86");
  assert.equal(first.summary?.subjectDigest, "872e54fcfa1100224729b4f4d02169ae48782325e1ccfc9c06bf6728bc5206b1");
  assert.equal(first.summary?.notAfter, "2027-01-28T22:39:29.108000Z");
  assert.equal(first.summary?.claims.length, 2);
});

test("tampered entries fail their checks", async () => {
  const record = JSON.parse(Buffer.from(parseBundle(bundle)[0]!).toString());
  const statement = Buffer.from(record.spec.data.content, "base64").toString().replace("mpm_d62bab1c86", "mpm_0000000000");
  record.spec.data.content = Buffer.from(statement).toString("base64");
  const e = await decodeEntry(bytes(JSON.stringify(record)));
  assert.deepEqual(e.checks, { contentHash: false, signature: false });
  assert.equal(e.summary?.subjectName, "mpm_0000000000");

  const junk = await decodeEntry(bytes("not json"));
  assert.ok(junk.error);
  assert.deepEqual(junk.checks, { contentHash: null, signature: null });
});

test("DER signature conversion", () => {
  const der = Uint8Array.from([0x30, 0x08, 0x02, 0x02, 0x00, 0x81, 0x02, 0x02, 0x01, 0x02]);
  assert.equal(hex(derSignatureToRaw(der, 2)), "00810102");
  assert.throws(() => derSignatureToRaw(der.subarray(0, 9), 2));
});

test("only strict DER signatures are accepted", () => {
  const seq = (...ints: number[][]) => {
    const body = ints.flatMap((i) => [0x02, i.length, ...i]);
    return Uint8Array.from([0x30, body.length, ...body]);
  };
  assert.equal(hex(derSignatureToRaw(seq([0x7f], [0x00, 0x80]), 2)), "007f0080");
  assert.throws(() => derSignatureToRaw(seq([0x80], [0x01]), 2), /negative/);
  assert.throws(() => derSignatureToRaw(seq([0x00, 0x01], [0x01]), 2), /not minimal/);
  assert.throws(() => derSignatureToRaw(seq([0x00, 0x00, 0x81], [0x01]), 2), /not minimal/);
  assert.throws(() => derSignatureToRaw(seq([], [0x01]), 2), /truncated/);
  assert.throws(() => derSignatureToRaw(seq([0x01, 0x02, 0x03], [0x01]), 2), /too large/);
  // A long-form length where the short form would do.
  assert.throws(() => derSignatureToRaw(Uint8Array.from([0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]), 2), /short form/);
});

/** The first real entry, with its JSON edited. */
function editedEntry(edit: (record: any) => void): Bytes {
  const record = JSON.parse(Buffer.from(parseBundle(bundle)[0]!).toString());
  edit(record);
  return bytes(JSON.stringify(record));
}

test("each part of an entry is checked and reported on its own", async () => {
  // A changed signature fails the signature check and nothing else.
  const badSig = await decodeEntry(editedEntry((r) => {
    const sig = Buffer.from(r.spec.signature.content, "base64");
    sig[sig.length - 1]! ^= 1;
    r.spec.signature.content = sig.toString("base64");
  }));
  assert.deepEqual(badSig.checks, { contentHash: true, signature: false });
  assert.equal(badSig.error, null);

  // An unreadable key fails the signature check but does not hide the statement.
  const badKey = await decodeEntry(editedEntry((r) => { r.spec.signature.publicKey.content = "bm90IGEga2V5"; }));
  assert.deepEqual(badKey.checks, { contentHash: true, signature: false });
  assert.match(badKey.keyError ?? "", /not a PEM public key/);
  assert.equal(badKey.summary?.subjectName, "mpm_d62bab1c86");

  // With no recorded digest the hash check is "not made", never "passed".
  const noHash = await decodeEntry(editedEntry((r) => { delete r.spec.data.hash; }));
  assert.deepEqual(noHash.checks, { contentHash: null, signature: true });

  // A key in PEM with CRLF line endings is still a key.
  const crlf = await decodeEntry(editedEntry((r) => {
    const pem = Buffer.from(r.spec.signature.publicKey.content, "base64").toString().replaceAll("\n", "\r\n");
    r.spec.signature.publicKey.content = Buffer.from(pem).toString("base64");
  }));
  assert.deepEqual(crlf.checks, { contentHash: true, signature: true });

  // The entry as logged is kept for display.
  assert.equal((await decodeEntry(parseBundle(bundle)[0]!)).recordText, Buffer.from(parseBundle(bundle)[0]!).toString());
});

test("a log client's requests can be cancelled", async () => {
  const abort = new AbortController();
  let seen: AbortSignal | null | undefined;
  const client = new LogClient("https://log.example/", async (_url, init) => {
    seen = init?.signal;
    return new Response("x");
  }, abort.signal);
  await client.checkpoint();
  assert.equal(seen, abort.signal);
});

test("checkBundle checks a bundle's entries against their leaf hashes", async () => {
  const client = new LogClient("https://log.example/", async (url) =>
    url === "https://log.example/tile/entries/000.p/7" ? new Response(bundle) : new Response("no", { status: 404 }));
  const leaves = tile0.subarray(0, 7 * 32);
  const all = await checkBundle(client, { index: 0, width: 7 }, 0, 7, leaves, null);
  assert.deepEqual(all.map((e) => e.index), [0, 1, 2, 3, 4, 5, 6]);
  assert.ok(all.every((e) => e.ok && e.inLog));
  assert.match(all[0]!.haystack, /mpm_d62bab1c86/);
  // What is kept per entry leaves out the parsed statement.
  assert.ok(!("statement" in all[0]!) && !("statementText" in all[0]!));
  assert.match(statementTextOf(all[0]!.recordText!) ?? "", /"name": "mpm_d62bab1c86"/);

  // Entries before `from` are already held and are skipped.
  assert.deepEqual((await checkBundle(client, { index: 0, width: 7 }, 5, 7, leaves, null)).map((e) => e.index), [5, 6]);

  // Against the wrong leaf hashes, nothing is in the log.
  const wrong = await checkBundle(client, { index: 0, width: 7 }, 0, 7, tile0.subarray(32, 8 * 32), null);
  assert.ok(wrong.every((e) => !e.inLog && !e.ok && e.checks.signature === true));

  const { root, interior } = await hashTree(tile0, 256);
  assert.equal(hex(root), hex(read("tile-1-000-first-hash.bin")));
  assert.equal(interior.length, 1);
});

// Inclusion proofs for leaves of paic.google.com/log/0, from
// golang.org/x/mod/sumdb/tlog: [tree size, leaf index, root, proof].
const PROOFS: [number, number, string, string[]][] = [
  [1, 0, "a42a259c56497e0a2ad88f13623e472ce4e1a53ec899228b20cee1781bb4f245", []],
  [2, 1, "455085e46707c789a0c7cf7b66f47f8fe8fb21a137cd87fe9dbb56e4e7ffdcc3", ["a42a259c56497e0a2ad88f13623e472ce4e1a53ec899228b20cee1781bb4f245"]],
  [7, 0, "4885b292c815ead602c7a85d905f2910394b2bd3e8695bc0ea79e8dd60a4fc79", ["83f3035abde75f849d23007acb95c28146ce8ae17889f250e5fbbcf49aa93b0a", "b2b02dc575fc7014b098fa61dd62f80d506936ed8309bd006880a319ca28a998", "efbc04277e08055144d234fff36e05746ca555a70e616d011fdaf23171585bae"]],
  [7, 3, "4885b292c815ead602c7a85d905f2910394b2bd3e8695bc0ea79e8dd60a4fc79", ["bce2c1a448f9069e242e762a5896a72a639bbf1a40bc9c986cfa0d82e57aea31", "455085e46707c789a0c7cf7b66f47f8fe8fb21a137cd87fe9dbb56e4e7ffdcc3", "efbc04277e08055144d234fff36e05746ca555a70e616d011fdaf23171585bae"]],
  [7, 6, "4885b292c815ead602c7a85d905f2910394b2bd3e8695bc0ea79e8dd60a4fc79", ["1ba96992032c8c3cbb2adfbcf8dca930679efdefe58f8e277e46d6f79d8e8721", "08505184983a190fa73bf7505a88d34d509d1278104e2fe5032cc9de3735db97"]],
  [200, 199, "b7d906943e0b5273343eb39a3015c6471cd62f423567116f1eddef434b2f94c8", ["9a63e139862be6fce1fedc6e5c03a1f74014fef3e4526105f50dd938b8f6bb83", "c27999fc4fe13a35f07fc072daf33920354cd7e5dc6aab454ea33b2d566d4bbc", "3d06c15acffe6a44bf15b34ab8558017e67e0935988aeb2263e6a818d7dbac64", "2d9cbbdaf000ae0d38dddbd480f9de735cc88fda7921c7b24a929261957f4893", "b21917fa459507660e8db70940835680e01266aa6cdcc108bc788042a3d34919"]],
  [201, 100, "62746dab65a01eaedf052d42cbeb16a770e57793c257155cbf39aa1bd2c0b98c", ["4ca2c8b24dd367106df70e7ab5d30a895cfca63175bda60881c06e71d9cc021c", "dc9cc5ee9b9bca8277f748c400e0ebe50d24af4283388171b1d21609e7e32240", "8590f24a0f30ae23cf0b878fcbda6a98e03edc19002021522fe1e1083c7803f6", "958b06ca57e7e620358a4a33be8ae6d4332564d97e8e3d9936d8ba0a706a70d8", "62ca0dac855f7a7329ccc85cebc490a6de311744efad537624132832c308b98b", "a87a1c4d6c298a5e76664b1c1028f0fbef5ab9227e4c9762ce2d6e9725b9799c", "3a8440cdd1ea7a139cb0025f71fedb51a1a68cfb0f28a18abae958079d989303", "d2a090c55d10348e697b55e514d174adef60f3801ad68777f3bbbc7a4d1234b6"]],
  [256, 255, "87dfb42cbab17c1658d776218231794b72a4e7ff99fc843f3d6d9837aa1ba5c0", ["e202264d253fb4ed7cd1c014d1e31859651b31683cc84664f270293f2eacca5a", "9ec9b6f3dd6852baf673047c275642e467faa4468f18e6b041a0ece75e1be046", "a0577f29537c9c9ecbbc6040a95b2c45a0283b27567b6bb43fea4e69a58c5597", "ab6c2977877f4f8bf0cf9a330fc2fb0d573c785555c88cb4a7c2a2c8c612c3e4", "24687021d1335efb296c8c18aa7cd20104f28fde1eafed918dc4f3f90d1ed47e", "09e26429dd59a065a989c6da35f2673e2fa351334aa7c41923519bc185a57453", "2d9cbbdaf000ae0d38dddbd480f9de735cc88fda7921c7b24a929261957f4893", "b21917fa459507660e8db70940835680e01266aa6cdcc108bc788042a3d34919"]],
];

test("inclusion proofs match the reference implementation's", async () => {
  for (const [size, index, root, want] of PROOFS) {
    const proof = await inclusionProof(tile0, index, size);
    assert.deepEqual(proof.map((h) => hex(h)), want, `size ${size}, leaf ${index}`);
    const leaf = tile0.subarray(index * 32, index * 32 + 32);
    assert.equal(hex(await rootFromInclusionProof(leaf, index, size, proof)), root);
  }
});

test("an inclusion proof proves one leaf of one tree and nothing else", async () => {
  const leaf = (i: number) => tile0.subarray(i * 32, i * 32 + 32);
  const proof = await inclusionProof(tile0, 100, 201);
  const root = hex(await rootFromLeafHashes(tile0, 201));
  assert.equal(hex(await rootFromInclusionProof(leaf(100), 100, 201, proof)), root);
  // Another leaf or another index gives some other root.
  assert.notEqual(hex(await rootFromInclusionProof(leaf(101), 100, 201, proof)), root);
  assert.notEqual(hex(await rootFromInclusionProof(leaf(100), 101, 201, proof)), root);
  await assert.rejects(rootFromInclusionProof(leaf(100), 100, 201, proof.slice(1)), /too short/);
  await assert.rejects(rootFromInclusionProof(leaf(100), 100, 201, [...proof, proof[0]!]), /too long/);
  await assert.rejects(inclusionProof(tile0, 201, 201), /no such leaf/);
});

test("tlog-proofs are written in the c2sp.org/tlog-proof form and read back", async () => {
  const checkpoint = "example.com/log\n7\n" + Buffer.from(await rootFromLeafHashes(tile0, 7)).toString("base64") + "\n\n— example.com/log AAAAAAAA\n";
  const hashes = await inclusionProof(tile0, 3, 7);
  const text = formatTlogProof({ index: 3, hashes, checkpoint });
  assert.equal(text, [
    "c2sp.org/tlog-proof@v1",
    "index 3",
    ...hashes.map((h) => Buffer.from(h).toString("base64")),
    "",
    checkpoint,
  ].join("\n"));
  const back = parseTlogProof(text);
  assert.equal(back.index, 3);
  assert.deepEqual(back.hashes.map((h) => hex(h)), hashes.map((h) => hex(h)));
  assert.equal(back.checkpoint, checkpoint);
  assert.throws(() => parseTlogProof(text.replace("@v1", "@v2")), /malformed/);
  assert.throws(() => parseTlogProof(text.replace("index 3", "index 03")), /malformed/);
});
