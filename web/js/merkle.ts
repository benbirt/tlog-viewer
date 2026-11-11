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
