// Following a log as it grows, without trusting it to have left alone what
// it already published.

import { type Bytes, bytesEqual } from "./bytes.js";
import { type LogClient, TILE_WIDTH, tilesForSize } from "./tiles.js";

export type Growth =
  /** The leaf hashes of the larger tree, the first `oldSize` of them unchanged. */
  | { kind: "extended"; leafHashes: Bytes }
  /** The log now serves a different hash for a leaf it had already published. */
  | { kind: "rewritten"; index: number };

/**
 * Extends the leaf hashes of a tree of `oldSize` leaves to `newSize`, fetching
 * only the tiles that can have changed: the one the old tree ended in, and
 * those after it. Where a fetched tile overlaps leaves already held, they must
 * be identical.
 *
 * Earlier tiles are not fetched again. The caller must still check that the
 * result hashes to the new checkpoint's root; because the old leaves are kept
 * rather than re-read, that check fails if the log has rewritten any of them,
 * which makes it a proof that the new tree extends the old one.
 */
export async function extendLeafHashes(client: LogClient, old: Bytes, oldSize: number, newSize: number): Promise<Growth> {
  if (newSize < oldSize || old.length < oldSize * 32) throw new Error("cannot extend to a smaller tree");
  const leafHashes = new Uint8Array(newSize * 32);
  leafHashes.set(old.subarray(0, oldSize * 32));
  const first = Math.floor(oldSize / TILE_WIDTH);
  let rewritten: number | null = null;
  await Promise.all(tilesForSize(newSize).slice(first).map(async (t) => {
    const tile = await client.hashTile(t);
    const start = t.index * TILE_WIDTH;
    for (let i = start; i < Math.min(oldSize, start + t.width); i++) {
      const served = tile.subarray((i - start) * 32, (i - start + 1) * 32);
      if (!bytesEqual(served, old.subarray(i * 32, i * 32 + 32)) && (rewritten === null || i < rewritten)) rewritten = i;
    }
    leafHashes.set(tile, start * 32);
  }));
  return rewritten === null ? { kind: "extended", leafHashes } : { kind: "rewritten", index: rewritten };
}
