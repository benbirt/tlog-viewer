import assert from "node:assert/strict";
import test from "node:test";
import type { Bytes } from "../web/js/bytes.js";
import { extendLeafHashes } from "../web/js/grow.js";
import { LogClient } from "../web/js/tiles.js";
import { siteVerifier } from "../tools/wasm.js";

const verifier = await siteVerifier(new URL("../site/", import.meta.url));

/** Follows a log from one size to another, fetching the tiles the verifier says can have changed. */
const extend = async (client: LogClient, old: Bytes, oldSize: number, newSize: number) =>
  extendLeafHashes(client, (await verifier.layout(oldSize, newSize)).tiles, old, oldSize, newSize);

/** Distinct 32-byte "hashes" for leaves 0..n-1. */
function leaves(n: number): Bytes {
  const out = new Uint8Array(n * 32);
  for (let i = 0; i < n; i++) new DataView(out.buffer).setUint32(i * 32, i + 1);
  return out;
}

/** A log client serving a tree of these leaves, recording what was asked for. */
async function serve(all: Bytes): Promise<{ client: LogClient; fetched: string[] }> {
  const size = all.length / 32;
  const tiles = new Map((await verifier.layout(0, size)).tiles.map((t) =>
    ["https://log.example/" + t.path, all.subarray(t.first * 32, (t.first + t.width) * 32)]));
  const fetched: string[] = [];
  const client = new LogClient("https://log.example/", async (url) => {
    fetched.push(url.replace("https://log.example/", ""));
    const body = tiles.get(url);
    return body ? new Response(body) : new Response("no", { status: 404 });
  });
  return { client, fetched };
}

test("a grown log is followed by fetching only the tiles that changed", async () => {
  const all = leaves(700);
  const { client, fetched } = await serve(all);
  const g = await extend(client, all.subarray(0, 600 * 32), 600, 700);
  assert.equal(g.kind, "extended");
  assert.deepEqual(g.kind === "extended" && g.leafHashes, all);
  // Leaves 0-255 and 256-511 sit in full tiles that cannot have changed.
  assert.deepEqual(fetched, ["tile/0/002.p/188"]);
});

test("growth across a tile boundary, and from an exact multiple of the tile width", async () => {
  const all = leaves(1030);
  const a = await serve(all);
  const g = await extend(a.client, all.subarray(0, 500 * 32), 500, 1030);
  assert.deepEqual(g.kind === "extended" && g.leafHashes, all);
  assert.deepEqual(a.fetched.sort(), ["tile/0/001", "tile/0/002", "tile/0/003", "tile/0/004.p/6"]);

  const b = await serve(all);
  const g2 = await extend(b.client, all.subarray(0, 512 * 32), 512, 1030);
  assert.deepEqual(g2.kind === "extended" && g2.leafHashes, all);
  assert.deepEqual(b.fetched.sort(), ["tile/0/002", "tile/0/003", "tile/0/004.p/6"]);

  const empty = await serve(leaves(3));
  const g3 = await extend(empty.client, new Uint8Array(0), 0, 3);
  assert.deepEqual(g3.kind === "extended" && g3.leafHashes, leaves(3));
});

test("a log that changes a leaf it already published is caught", async () => {
  const before = leaves(600);
  const after = leaves(700);
  after[590 * 32 + 5]! ^= 1;
  after[530 * 32 + 5]! ^= 1;
  const g = await extend((await serve(after)).client, before, 600, 700);
  assert.deepEqual(g, { kind: "rewritten", index: 530 });
});

test("shrinking is refused", async () => {
  await assert.rejects(extend((await serve(leaves(5))).client, leaves(10), 10, 5), /smaller tree/);
});
