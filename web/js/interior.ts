// Checks a log's hash tiles above level 0 against its leaves.

import { type Bytes, bytesEqual } from "./bytes.js";
import { interiorTileHashes } from "./merkle.js";
import { type LogClient, TILE_WIDTH, tilePath, tilesForSize } from "./tiles.js";

export interface InteriorTileResult {
  /** How many interior tiles the log should have at this size; all were fetched. */
  checked: number;
  /** Paths of the tiles whose contents differ from what the leaves imply. */
  mismatched: string[];
}

/**
 * Fetches every interior hash tile of a log of `size` leaves and compares it
 * with the hashes recomputed from `leafHashes`. Verifying the log does not
 * need these tiles, but a log that serves ones inconsistent with its leaves is
 * broken. A tile that cannot be fetched is an error, not a mismatch.
 */
export async function verifyInteriorTiles(
  client: LogClient, leafHashes: Bytes, size: number, expected?: Bytes[],
): Promise<InteriorTileResult> {
  const result: InteriorTileResult = { checked: 0, mismatched: [] };
  // `expected` is interiorTileHashes(leafHashes, size), if already computed.
  const levels = expected ?? await interiorTileHashes(leafHashes, size);
  for (const [i, expected] of levels.entries()) {
    const level = i + 1;
    await Promise.all(tilesForSize(expected.length / 32).map(async (t) => {
      const served = await client.hashTile(t, level);
      const start = t.index * TILE_WIDTH * 32;
      if (!bytesEqual(served, expected.subarray(start, start + t.width * 32))) {
        result.mismatched.push(tilePath(level, t.index, t.width));
      }
      result.checked++;
    }));
  }
  result.mismatched.sort();
  return result;
}
