// The heavy part of loading a log: fetching, hashing and checking its entries.
// It has no DOM dependencies, so it runs in workers (worker.ts), keeping the
// page responsive however large the log is.

import { type Bytes, bytesEqual, concat, sha256 } from "./bytes.js";
import { type DecodedEntry, decodeEntry } from "./entry.js";
import { type Fault, faultTargets } from "./faults.js";
import { type LogClient, TILE_WIDTH, type TileRef } from "./tiles.js";

/**
 * A decoded entry plus what was established about its place in the log. The
 * parsed statement and its text are left out: they can be recovered from
 * `recordText` when an entry is opened, and keeping them for every entry
 * would more than double what a large log costs in memory.
 */
export interface CheckedEntry extends Omit<DecodedEntry, "statement" | "statementText"> {
  index: number;
  leafHash: Bytes;
  /** Whether the entry hashes to the leaf the log committed to. */
  inLog: boolean;
  /** Whether every check passed. */
  ok: boolean;
  /** Lower-cased text the search box matches against. */
  haystack: string;
}

/**
 * The hash of an entry as a leaf of the log's tree: SHA-256 of a zero byte and
 * the entry (RFC 6962). Everything above the leaves is hashed by the verifier.
 */
export const leafHash = (entry: Bytes): Promise<Bytes> => sha256(concat(Uint8Array.of(0), entry));

function haystack(index: number, e: DecodedEntry): string {
  const s = e.summary;
  if (!s) return String(index);
  return [index, s.subjectName, s.subjectDigest, s.workload, s.version, s.publisher, s.artifact,
    e.keyFingerprint, ...s.claims.map((c) => c.type)].filter((x) => x != null).join("\n").toLowerCase();
}

/**
 * Fetches one entry bundle and checks each entry from index `from` on against
 * its leaf hash, its recorded digest and its signature. `tileLeafHashes` are
 * the verified leaf hashes of this tile's entries; `size` is the tree's.
 */
export async function checkBundle(
  client: LogClient, tile: TileRef, from: number, size: number, tileLeafHashes: Bytes, fault: Fault | null,
): Promise<CheckedEntry[]> {
  const bundle = await client.entryBundle(tile);
  const altered = fault?.entry ? faultTargets(size) : [];
  const out: CheckedEntry[] = [];
  for (const [i, served] of bundle.entries()) {
    const index = tile.index * TILE_WIDTH + i;
    if (index < from) continue;
    // A simulated failure alters an entry either as served, before it is
    // compared with its leaf hash, or as if logged that way, after.
    const rewrite = fault?.entry && altered.includes(index) ? fault.entry : null;
    const bytes = rewrite && fault?.entryStage === "served" ? rewrite(served) : served;
    const lh = await leafHash(bytes);
    const decoded = await decodeEntry(rewrite && fault?.entryStage === "logged" ? rewrite(bytes) : bytes);
    const inLog = bytesEqual(lh, tileLeafHashes.subarray(i * 32, i * 32 + 32));
    const { statement: _statement, statementText: _text, ...kept } = decoded;
    out.push({
      ...kept,
      index,
      leafHash: lh,
      inLog,
      ok: inLog && !decoded.error && decoded.checks.contentHash === true && decoded.checks.signature === true,
      haystack: haystack(index, decoded),
    });
  }
  return out;
}
