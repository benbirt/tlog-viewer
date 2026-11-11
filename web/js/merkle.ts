// RFC 6962 Merkle tree hashing.

import { type Bytes, concat, sha256 } from "./bytes.js";

const LEAF = Uint8Array.of(0);
const NODE = Uint8Array.of(1);

export const leafHash = (entry: Bytes): Promise<Bytes> => sha256(concat(LEAF, entry));
const nodeHash = (left: Bytes, right: Bytes): Promise<Bytes> => sha256(concat(NODE, left, right));

/**
 * Computes the tree head over `count` leaf hashes packed 32 bytes each in
 * `hashes`. An empty tree hashes to SHA-256 of the empty string.
 */
export async function rootFromLeafHashes(hashes: Bytes, count: number = hashes.length / 32): Promise<Bytes> {
  if (!Number.isInteger(count) || hashes.length < count * 32) throw new Error("not enough leaf hashes");
  // Stack of complete subtrees, largest at the bottom.
  const stack: { h: Bytes; height: number }[] = [];
  for (let i = 0; i < count; i++) {
    let h = hashes.subarray(i * 32, i * 32 + 32);
    let height = 0;
    for (let top = stack.at(-1); top && top.height === height; top = stack.at(-1)) {
      stack.pop();
      h = await nodeHash(top.h, h);
      height++;
    }
    stack.push({ h, height });
  }
  let root = stack.pop()?.h;
  if (!root) return sha256(new Uint8Array(0));
  for (let next = stack.pop(); next; next = stack.pop()) root = await nodeHash(next.h, root);
  return root;
}

/**
 * Computes what a log's hash tiles above level 0 must contain. A hash at tile
 * level k is the head of a complete subtree of 256^k leaves, so each level is
 * the previous one hashed up in groups of 256, ignoring an incomplete final
 * group. Element k-1 of the result packs the hashes of level k; levels that
 * would be empty are omitted.
 */
export async function interiorTileHashes(leafHashes: Bytes, count: number = leafHashes.length / 32): Promise<Bytes[]> {
  const GROUP = 256 * 32;
  const levels: Bytes[] = [];
  let below = leafHashes.subarray(0, count * 32);
  for (;;) {
    const n = Math.floor(below.length / GROUP);
    if (n === 0) return levels;
    const level = new Uint8Array(n * 32);
    for (let i = 0; i < n; i++) {
      level.set(await rootFromLeafHashes(below.subarray(i * GROUP, (i + 1) * GROUP)), i * 32);
    }
    levels.push(level);
    below = level;
  }
}

/** The largest power of two smaller than n, for n > 1. */
function splitPoint(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/**
 * The inclusion proof (RFC 6962 audit path) for leaf `index` in the tree of
 * the first `size` leaf hashes: the sibling hashes from the leaf up to the
 * root.
 */
export async function inclusionProof(leafHashes: Bytes, index: number, size: number): Promise<Bytes[]> {
  if (!Number.isInteger(index) || index < 0 || index >= size || leafHashes.length < size * 32) {
    throw new Error("no such leaf");
  }
  const path = async (m: number, leaves: Bytes): Promise<Bytes[]> => {
    const n = leaves.length / 32;
    if (n === 1) return [];
    const k = splitPoint(n);
    const left = leaves.subarray(0, k * 32);
    const right = leaves.subarray(k * 32);
    return m < k
      ? [...await path(m, left), await rootFromLeafHashes(right)]
      : [...await path(m - k, right), await rootFromLeafHashes(left)];
  };
  return path(index, leafHashes.subarray(0, size * 32));
}

/**
 * The root implied by an inclusion proof, as a verifier holding only the leaf
 * hash, its index and the tree size would compute it (RFC 9162, 2.1.3.2).
 */
export async function rootFromInclusionProof(leaf: Bytes, index: number, size: number, proof: Bytes[]): Promise<Bytes> {
  if (index < 0 || index >= size) throw new Error("no such leaf");
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    if (sn === 0) throw new Error("inclusion proof is too long");
    if (fn % 2 === 1 || fn === sn) {
      r = await nodeHash(p, r);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      r = await nodeHash(r, p);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  if (sn !== 0) throw new Error("inclusion proof is too short");
  return r;
}
