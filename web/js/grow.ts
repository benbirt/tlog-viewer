// Following a log as it grows, without trusting it to have left alone what
// it already published.

import { type Bytes, bytesEqual } from "./bytes.js";
import type { LogClient } from "./tiles.js";
import type { TileRef } from "./verifier.js";

export type Growth =
  /** The leaf hashes of the larger tree, the first `oldSize` of them unchanged. */
  | { kind: "extended"; leafHashes: Bytes }
  /** The log now serves a different hash for a leaf it had already published. */
  | { kind: "rewritten"; index: number };

/**
 * Extends the leaf hashes of a tree of `oldSize` leaves to `newSize`, fetching
 * `tiles`: those that can have changed, which the verifier's layout names as
 * the one the old tree ended in and those after it. Where a fetched tile
 * overlaps leaves already held, they must be identical.
 *
 * Earlier tiles are not fetched again. The caller must still check that the
 * result hashes to the new checkpoint's root; because the old leaves are kept
 * rather than re-read, that check fails if the log has rewritten any of them,
 * which makes it a proof that the new tree extends the old one.
 */
export async function extendLeafHashes(client: LogClient, tiles: TileRef[], old: Bytes, oldSize: number, newSize: number): Promise<Growth> {
  if (newSize < oldSize || old.length < oldSize * 32) throw new Error("cannot extend to a smaller tree");
  const leafHashes = new Uint8Array(newSize * 32);
  leafHashes.set(old.subarray(0, oldSize * 32));
  let rewritten: number | null = null;
  await Promise.all(tiles.map(async (t) => {
    const tile = await client.hashTile(t);
    for (let i = t.first; i < Math.min(oldSize, t.first + t.width); i++) {
      const served = tile.subarray((i - t.first) * 32, (i - t.first + 1) * 32);
      if (!bytesEqual(served, old.subarray(i * 32, i * 32 + 32)) && (rewritten === null || i < rewritten)) rewritten = i;
    }
    leafHashes.set(tile, t.first * 32);
  }));
  return rewritten === null ? { kind: "extended", leafHashes } : { kind: "rewritten", index: rewritten };
}
