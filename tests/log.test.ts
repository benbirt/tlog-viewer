import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { type Bytes, hex } from "../web/js/bytes.js";
import { decodeEntry, derSignatureToRaw, statementTextOf } from "../web/js/entry.js";
import { checkBundle, leafHash } from "../web/js/ingest.js";
import { verifyInteriorTiles } from "../web/js/interior.js";
import { encodeIndex, HttpError, LogClient, parseBundle, tilePath, tilesForSize } from "../web/js/tiles.js";
import { siteVerifier } from "../tools/wasm.js";

const read = (f: string): Bytes => new Uint8Array(readFileSync(new URL("testdata/" + f, import.meta.url)));
const bytes = (s: string): Bytes => new Uint8Array(Buffer.from(s));
const bundle = read("entries-first7.bin");
const tile0 = read("tile-0-000.bin");
const verifier = await siteVerifier(new URL("../site/", import.meta.url));

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

test("interior tiles are checked against what the leaves imply", async () => {
  // A log of 600 leaves has one partial level-1 tile holding two hashes.
  const leaves = new Uint8Array(600 * 32);
  for (let i = 0; i < leaves.length; i++) leaves[i] = (i * 7) & 0xff;
  const { interior } = await verifier.tree(leaves, 600);
  const tile = interior[0]!.data;
  const serve = (body: Bytes) => new LogClient("https://log.example/", async (url) =>
    url === "https://log.example/tile/1/000.p/2" ? new Response(body) : new Response("no", { status: 404 }));

  assert.deepEqual(await verifyInteriorTiles(serve(tile), interior), { checked: 1, mismatched: [] });

  const corrupt = tile.slice();
  corrupt[40]! ^= 1;
  assert.deepEqual(await verifyInteriorTiles(serve(corrupt), interior), { checked: 1, mismatched: ["tile/1/000.p/2"] });

  // Too small for interior tiles: nothing is fetched.
  assert.deepEqual(await verifyInteriorTiles(serve(tile), (await verifier.tree(leaves, 255)).interior), { checked: 0, mismatched: [] });
  // A missing tile is an error, not a pass.
  await assert.rejects(verifyInteriorTiles(serve(tile), (await verifier.tree(leaves, 300)).interior), (e) => e instanceof HttpError);
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


test("ECDSA signatures are read only as strict DER", () => {
  // A real signature from the log: SEQUENCE { INTEGER r, INTEGER s }.
  const record = JSON.parse(Buffer.from(parseBundle(bundle)[0]!).toString());
  const der: Bytes = new Uint8Array(Buffer.from(record.spec.signature.content, "base64"));
  const rLen = der[3]!;
  const r = [...der.subarray(4, 4 + rLen)];
  const s = [...der.subarray(6 + rLen)];
  const seq = (a: number[], b: number[]): Bytes =>
    Uint8Array.from([0x30, a.length + b.length + 4, 0x02, a.length, ...a, 0x02, b.length, ...b]);
  assert.deepEqual(seq(r, s), der);

  const unsigned = (v: number[]) => hex(Uint8Array.from(v)).replace(/^00(?=[89a-f])/, "").padStart(64, "0");
  assert.equal(hex(derSignatureToRaw(der)), unsigned(r) + unsigned(s));

  const cases: [string, Bytes][] = [
    ["an integer with a needless leading zero", seq([0, ...r], s)],
    ["a negative integer", seq(r[0] === 0 ? r.slice(1) : [r[0]! | 0x80, ...r.slice(1)], s)],
    ["a length in long form", Uint8Array.from([0x30, 0x81, der[1]!, ...der.subarray(2)])],
    ["trailing data", Uint8Array.from([...der, 0])],
    ["a truncated signature", der.subarray(0, der.length - 1)],
    ["an empty integer", seq([], s)],
    ["not a sequence", Uint8Array.from([0x31, ...der.subarray(1)])],
  ];
  for (const [what, bytes] of cases) assert.throws(() => derSignatureToRaw(bytes), Error, what);
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
});

test("signing keys are read by kind, and fingerprinted as their SubjectPublicKeyInfo", async () => {
  // A real key: its fingerprint is the SHA-256 of the DER inside the PEM.
  const record = JSON.parse(Buffer.from(parseBundle(bundle)[0]!).toString());
  const pem = Buffer.from(record.spec.signature.publicKey.content, "base64").toString();
  const der = Buffer.from(pem.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");
  const real = await decodeEntry(parseBundle(bundle)[0]!);
  assert.equal(real.keyFingerprint, createHash("sha256").update(der).digest("hex"));

  // A key of another kind is recognised and fingerprinted, and its signature
  // reported as not checked: this page verifies ECDSA P-256 only.
  const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-384" });
  const p384 = publicKey.export({ type: "spki", format: "pem" }) as string;
  const other = await decodeEntry(editedEntry((r) => { r.spec.signature.publicKey.content = Buffer.from(p384).toString("base64"); }));
  assert.deepEqual(other.checks, { contentHash: true, signature: null });
  assert.equal(other.keyError, null);
  assert.equal(other.keyFingerprint, createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex"));

  // A private key, or anything else in PEM armour, is not a public key.
  const junk = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
  const bad = await decodeEntry(editedEntry((r) => { r.spec.signature.publicKey.content = Buffer.from(junk).toString("base64"); }));
  assert.deepEqual(bad.checks, { contentHash: true, signature: false });
  assert.match(bad.keyError ?? "", /not a PEM public key/);
});
