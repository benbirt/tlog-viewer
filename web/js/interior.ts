// Checks a log's hash tiles above level 0 against its leaves.

import { bytesEqual } from "./bytes.js";
import { type LogClient, tilePath } from "./tiles.js";
import type { Tile } from "./verifier.js";

export interface InteriorTileResult {
  /** How many interior tiles the log should have at this size; all were fetched. */
  checked: number;
  /** Paths of the tiles whose contents differ from what the leaves imply. */
  mismatched: string[];
}

/**
 * Fetches every interior hash tile of a log and compares it with `expected`,
 * what the verifier computed those tiles must hold from the leaf hashes.
 * Verifying the log does not need these tiles, but a log that serves ones
 * inconsistent with its leaves is broken. A tile that cannot be fetched is an
 * error, not a mismatch.
 */
export async function verifyInteriorTiles(client: LogClient, expected: Tile[]): Promise<InteriorTileResult> {
  const result: InteriorTileResult = { checked: 0, mismatched: [] };
  await Promise.all(expected.map(async (t) => {
    const served = await client.hashTile(t, t.level);
    if (!bytesEqual(served, t.data)) result.mismatched.push(tilePath(t.level, t.index, t.width));
    result.checked++;
  }));
  result.mismatched.sort();
  return result;
}
