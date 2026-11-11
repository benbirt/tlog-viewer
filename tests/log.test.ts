import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { type Bytes, hex } from "../web/js/bytes.js";
import { decodeEntry, derSignatureToRaw } from "../web/js/entry.js";
import { verifyInteriorTiles } from "../web/js/interior.js";
import { interiorTileHashes, leafHash, rootFromLeafHashes } from "../web/js/merkle.js";
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
