// Failures the viewer can simulate, so that its behaviour under them can be
// seen without waiting for a log to misbehave. Each alters data after it has
// been fetched; nothing here can make a check pass that would otherwise fail.

import { b64Decode, b64Encode, type Bytes, utf8Decode, utf8Encode } from "./bytes.js";
import { ALG_MLDSA44 } from "./policy.js";
import type { Fetch } from "./tiles.js";

export interface Fault {
  id: string;
  title: string;
  /** What is altered and what the page should then show. */
  description: string;
  /** Rewrites the signed checkpoint as fetched. */
  checkpoint?: (raw: string) => string;
  /** Serves the checkpoint of a different log in the policy. */
  checkpointFromOtherLog?: boolean;
  /** Rewrites a tile, given its path relative to the log; "error" fails the request. */
  tile?: (path: string, bytes: Bytes) => Bytes | "error";
  /**
   * Rewrites an entry. With `entryStage` "served" the change is made to what
   * the log serves, so the entry no longer matches its leaf hash. With
   * "logged" it is made after that comparison, to show an entry that really
   * is in the log but is itself bad: a real log cannot be made to contain one
   * from here.
   */
  entry?: (bytes: Bytes) => Bytes;
  entryStage?: "served" | "logged";
  /** Signature algorithms to treat as unsupported by this browser. */
  disabledAlgs?: number[];
  /** Moves the page's idea of the current time forward. */
  clockOffsetMs?: number;
}

/** Entries a fault's `entry` rewrite applies to: the newest, and one a little older. */
export function faultTargets(size: number): number[] {
  return [size - 1, size - 3].filter((i) => i >= 0);
}

function flipLastByte(bytes: Bytes): Bytes {
  const out = bytes.slice();
  if (out.length > 0) out[out.length - 1]! ^= 1;
  return out;
}

function flipFirstByte(bytes: Bytes): Bytes {
  const out = bytes.slice();
  if (out.length > 0) out[0]! ^= 1;
  return out;
}

/**
 * Rewrites a checkpoint's signature lines. `edit` gets each line's signer,
 * whether that signer is the log (its name is the origin), and the line's
 * position among those of its kind; it returns "keep", "corrupt" or "drop".
 */
function editSignatures(
  raw: string, edit: (line: { isLog: boolean; nth: number; last: boolean }) => "keep" | "corrupt" | "drop",
): string {
  const split = raw.lastIndexOf("\n\n");
  if (split < 0) return raw;
  const origin = raw.slice(0, raw.indexOf("\n"));
  const lines = raw.slice(split + 2).split("\n").filter((l) => l !== "");
  const counts = { log: 0, witness: 0 };
  const out: string[] = [];
  lines.forEach((line, i) => {
    const m = /^— (\S+) (\S+)$/.exec(line);
    if (!m) return void out.push(line);
    const isLog = m[1] === origin;
    const action = edit({ isLog, nth: isLog ? counts.log++ : counts.witness++, last: i === lines.length - 1 });
    if (action === "keep") out.push(line);
    if (action === "corrupt") out.push(`— ${m[1]} ${b64Encode(flipLastByte(b64Decode(m[2]!)))}`);
  });
  return raw.slice(0, split + 2) + out.map((l) => l + "\n").join("");
}

/** Rewrites the JSON of a hashedrekord entry. */
function editRecord(bytes: Bytes, edit: (spec: any) => void): Bytes {
  const record = JSON.parse(utf8Decode(bytes));
  edit(record.spec);
  return utf8Encode(JSON.stringify(record));
}

const b64Text = (s: string) => b64Encode(utf8Encode(s));

export const FAULTS: Fault[] = [
  {
    id: "log-signature",
    title: "Log signature invalid",
    description: "Every signature by the log is corrupted. The checkpoint is rejected and nothing from the log is shown.",
    checkpoint: (raw) => editSignatures(raw, (l) => (l.isLog ? "corrupt" : "keep")),
  },
  {
    id: "one-log-signature",
    title: "One of the log's signatures invalid",
    description: "The first of the log's signatures is corrupted. If the log signs with a second key the checkpoint still stands, with a warning.",
    checkpoint: (raw) => editSignatures(raw, (l) => (l.isLog && l.nth === 0 ? "corrupt" : "keep")),
  },
  {
    id: "witness-signature",
    title: "One cosignature invalid",
    description: "The last cosignature is corrupted. The quorum tolerates one faulty witness, so the checkpoint stands, with a warning.",
    checkpoint: (raw) => editSignatures(raw, (l) => (l.last && !l.isLog ? "corrupt" : "keep")),
  },
  {
    id: "no-quorum",
    title: "Too few cosignatures",
    description: "All cosignatures but the first are removed. The quorum is not met, so nothing from the log is shown.",
    checkpoint: (raw) => editSignatures(raw, (l) => (l.isLog || l.nth === 0 ? "keep" : "drop")),
  },
  {
    id: "wrong-log",
    title: "Another log's checkpoint",
    description: "The checkpoint of a different log in the policy is served in place of this one's. It is validly signed and witnessed, but for the wrong log.",
    checkpointFromOtherLog: true,
  },
  {
    id: "stale-checkpoint",
    title: "Checkpoint not witnessed recently",
    description: "The page behaves as if it were three days from now, so the cosignatures look old. Validity periods are judged against that date too.",
    clockOffsetMs: 3 * 24 * 60 * 60 * 1000,
  },
  {
    id: "no-ml-dsa",
    title: "Browser without ML-DSA-44",
    description: "ML-DSA-44 signatures are treated as uncheckable, as in a browser whose WebCrypto lacks the algorithm.",
    disabledAlgs: [ALG_MLDSA44],
  },
  {
    id: "leaf-hashes",
    title: "Leaf hashes do not match the checkpoint",
    description: "One hash in the first leaf-hash tile is altered. The recomputed root differs from the witnessed one, so nothing from the log is shown.",
    tile: (path, bytes) => (/^tile\/0\/000(\.p\/\d+)?$/.test(path) ? flipFirstByte(bytes) : bytes),
  },
  {
    id: "interior-tile",
    title: "Interior tile does not match the leaves",
    description: "One hash in a level-1 tile is altered. The entries still verify against the checkpoint, but the log is serving an inconsistent tile. Logs under 256 entries have no such tile.",
    tile: (path, bytes) => (/^tile\/1\//.test(path) ? flipFirstByte(bytes) : bytes),
  },
  {
    id: "tile-unavailable",
    title: "A tile cannot be fetched",
    description: "Requests for the oldest entry bundle fail, as if the server returned an error.",
    tile: (path, bytes) => (/^tile\/entries\/000(\.p\/\d+)?$/.test(path) ? "error" : bytes),
  },
  {
    id: "entry-swapped",
    title: "Entries served differ from the log",
    description: "Two recent entries are altered as served, so they no longer hash to the leaves the log committed to.",
    entryStage: "served",
    entry: (bytes) => editRecord(bytes, (spec) => { spec.debugAltered = true; }),
  },
  {
    id: "entry-signature",
    title: "Logged entries with bad signatures",
    description: "Two recent entries are shown as if the log had recorded them with signatures that do not verify.",
    entryStage: "logged",
    entry: (bytes) => editRecord(bytes, (spec) => {
      spec.signature.content = b64Encode(flipLastByte(b64Decode(spec.signature.content)));
    }),
  },
  {
    id: "entry-content",
    title: "Logged entries with altered statements",
    description: "Two recent entries are shown as if their statements had been changed after signing: the recorded hash and the signature both fail.",
    entryStage: "logged",
    entry: (bytes) => editRecord(bytes, (spec) => {
      const statement = utf8Decode(b64Decode(spec.data.content));
      spec.data.content = b64Text(statement.replace(/"name":\s*"/, (m) => m + "altered-"));
    }),
  },
  {
    id: "entry-key",
    title: "Logged entries with unreadable keys",
    description: "Two recent entries are shown as if recorded with something that is not a public key. The statement can still be read.",
    entryStage: "logged",
    entry: (bytes) => editRecord(bytes, (spec) => { spec.signature.publicKey.content = b64Text("not a key"); }),
  },
  {
    id: "entry-garbage",
    title: "Logged entries that are not endorsements",
    description: "Two recent entries are shown as if the log had recorded arbitrary bytes.",
    entryStage: "logged",
    entry: () => utf8Encode("this is not a hashedrekord"),
  },
];

export const faultById = (id: string | null): Fault | null => FAULTS.find((f) => f.id === id) ?? null;

/** Wraps a fetch for the log at `base` so that it applies a fault's checkpoint and tile rewrites. */
export function faultyFetch(fault: Fault, base: string, inner: Fetch = (url, init) => fetch(url, init)): Fetch {
  return async (url, init) => {
    const res = await inner(url, init);
    if (!res.ok || !url.startsWith(base)) return res;
    const path = url.slice(base.length);
    if (path === "checkpoint" && fault.checkpoint) {
      return new Response(fault.checkpoint(await res.text()));
    }
    if (path.startsWith("tile/") && fault.tile) {
      const out = fault.tile(path, new Uint8Array(await res.arrayBuffer()));
      return out === "error" ? new Response("simulated failure", { status: 503 }) : new Response(out);
    }
    return res;
  };
}
