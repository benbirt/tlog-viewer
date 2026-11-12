// The page's access to the verifier: the Go implementations of the
// transparency formats (github.com/transparency-dev/formats and
// golang.org/x/mod/sumdb/tlog), compiled to WebAssembly from //verifier and
// run in workers (gowasm.ts). Policies, signed checkpoints, cosignatures, the
// Merkle tree, proofs, and where a log keeps its tiles and what is in them are
// all read, checked and written there. This module only carries the questions
// and answers across.

import { b64Decode, type Bytes, fromHex } from "./bytes.js";

/** A key in the trust policy. */
export interface PolicyKey {
  /** The key's name: for a log, its origin. */
  name: string;
  keyId: number;
  alg: string;
  vkey: string;
  /** The policy's own name for a witness. */
  witness?: string;
}

export interface PolicyInfo {
  /** The distinct logs the policy trusts, in order of first mention. */
  origins: string[];
  logs: PolicyKey[];
  witnesses: PolicyKey[];
  groups: { name: string; threshold: number; members: string[] }[];
  /** The witness or group that must have cosigned, or "none". */
  quorum: string;
}

/** The quorum rule, evaluated against the cosignatures on a checkpoint. */
export interface QuorumNode {
  name: string;
  kind: "witness" | "group" | "none";
  satisfied: boolean;
  threshold?: number;
  count: number;
  children?: QuorumNode[];
}

export interface SignatureResult {
  name: string;
  keyId: number;
  role: "log" | "witness" | "unknown";
  /** The policy's name for a witness. */
  witness: string | null;
  algName: string | null;
  status: "valid" | "invalid" | "unknown-key";
  /** A valid cosignature's time, in Unix seconds. */
  timestamp: bigint | null;
}

export interface Checkpoint {
  origin: string;
  size: number;
  hash: Bytes;
  extensions: string[];
}

export interface CheckpointResult {
  checkpoint: Checkpoint;
  /** The signed text of the note. */
  text: string;
  signatures: SignatureResult[];
  logSigned: boolean;
  quorum: QuorumNode;
  /**
   * When the quorum was reached, in Unix seconds: the latest time such that
   * the cosignatures made at or after it are enough on their own. Null if the
   * quorum is not met or needs no cosignatures.
   */
  witnessedAt: bigint | null;
  /** False if there are extension lines that no valid log signature covers. */
  extensionsAuthenticated: boolean;
  /** Reasons the checkpoint may not be relied on. */
  problems: string[];
  /** Anomalies that do not change the verdict, such as a bad signature beside good ones. */
  warnings: string[];
  ok: boolean;
}

/** A level-0 tile of a log and the entry bundle beside it. */
export interface TileRef {
  index: number;
  /** The number of hashes in the tile, and of entries in the bundle. */
  width: number;
  /** The index in the log of the tile's first leaf. */
  first: number;
  /** Where the tile and its entry bundle are served, relative to the log's URL. */
  path: string;
  entries: string;
}

export interface Layout {
  /** Where the log serves its checkpoint. */
  checkpoint: string;
  tiles: TileRef[];
}

export interface Tile {
  level: number;
  index: number;
  width: number;
  data: Bytes;
  /** Where the log serves the tile, relative to its URL. */
  path: string;
}

export interface TreeHashes {
  root: Bytes;
  /** What the log's tiles above level 0 must contain. */
  interior: Tile[];
}

export interface ProofCheck {
  ok: boolean;
  error?: string;
  index: number;
  origin: string;
  size: number;
}

export interface Verifier {
  /** Reads a trust policy; rejects if it is not one. */
  policy(text: string): Promise<PolicyInfo>;
  /**
   * Judges a signed checkpoint under a policy, as the checkpoint of the log
   * `expectedOrigin`. Rejects if it is not a signed checkpoint at all.
   */
  checkpoint(policyText: string, raw: string, expectedOrigin: string): Promise<CheckpointResult>;
  /**
   * Where a log keeps the leaves from tree size `from` up to `size`: the
   * tiles to fetch to follow a log that has grown, or all of them from 0.
   */
  layout(from: number, size: number): Promise<Layout>;
  /** Splits an entry bundle into its entries. */
  splitBundle(bundle: Bytes): Promise<Bytes[]>;
  /** The hash of an entry as a leaf of the tree. */
  leafHash(entry: Bytes): Promise<Bytes>;
  /** Hashes the tree of the first `size` leaf hashes. */
  tree(leafHashes: Bytes, size: number): Promise<TreeHashes>;
  /** Writes the c2sp.org/tlog-proof for one leaf under a signed checkpoint. */
  prove(leafHashes: Bytes, size: number, index: number, checkpoint: string): Promise<string>;
  /** Checks a tlog-proof for an entry with the given leaf hash, as its recipient would. */
  checkProof(policyText: string, proof: string, leafHash: Bytes): Promise<ProofCheck>;
}

/** Calls one of the WebAssembly module's functions: most reply in JSON, a few with bytes. */
export type Call = (fn: string, ...args: unknown[]) => Promise<unknown>;

interface WireSignature {
  name: string;
  keyId: number;
  role: "log" | "witness" | "unknown";
  witness?: string;
  alg?: string;
  status: "valid" | "invalid" | "unknown-key";
  timestamp?: string;
}

/** A Verifier over some way of calling the WebAssembly module. */
export function verifierOver(call: Call): Verifier {
  const ask = async <T>(fn: string, ...args: unknown[]): Promise<T> => {
    const reply = await call(fn, ...args);
    if (typeof reply !== "string") throw new Error(`the verifier gave no answer to ${fn}`);
    return JSON.parse(reply) as T;
  };
  return {
    async policy(text) {
      const out = await ask<PolicyInfo & { error?: string }>("tlogPolicy", JSON.stringify(text));
      if (out.error !== undefined) throw new Error(`the trust policy cannot be read: ${out.error}`);
      return out;
    },

    async checkpoint(policyText, raw, expectedOrigin) {
      const out = await ask<{
        malformed?: string; ok: boolean; problems: string[]; warnings: string[]; text: string;
        origin: string; size: string; hash: string; extensions: string[]; signatures: WireSignature[];
        logSigned: boolean; quorum: QuorumNode; witnessedAt?: string; extensionsAuthenticated: boolean;
      }>("tlogCheckpoint", JSON.stringify({ policy: policyText, checkpoint: raw, expectedOrigin }));
      if (out.malformed !== undefined) throw new Error(`malformed checkpoint: ${out.malformed}`);
      const size = Number(out.size);
      if (!Number.isSafeInteger(size)) throw new Error("malformed checkpoint: size too large");
      return {
        checkpoint: { origin: out.origin, size, hash: b64Decode(out.hash), extensions: out.extensions },
        text: out.text,
        signatures: out.signatures.map((s) => ({
          name: s.name, keyId: s.keyId, role: s.role, witness: s.witness ?? null, algName: s.alg ?? null,
          status: s.status, timestamp: s.timestamp !== undefined ? BigInt(s.timestamp) : null,
        })),
        logSigned: out.logSigned,
        quorum: out.quorum,
        witnessedAt: out.witnessedAt !== undefined ? BigInt(out.witnessedAt) : null,
        extensionsAuthenticated: out.extensionsAuthenticated,
        problems: out.problems,
        warnings: out.warnings,
        ok: out.ok,
      };
    },

    layout: (from, size) => ask<Layout>("tlogLayout", JSON.stringify({ from, size })),

    async splitBundle(bundle) {
      const reply = await call("tlogBundle", bundle);
      if (typeof reply === "string") throw new Error(`malformed entry bundle: ${(JSON.parse(reply) as { error: string }).error}`);
      return reply as Bytes[];
    },

    leafHash: async (entry) => (await call("tlogLeafHash", entry)) as Bytes,

    async tree(leafHashes, size) {
      const out = await ask<{ error?: string; root: string; interior: (Omit<Tile, "data"> & { data: string })[] }>(
        "tlogTree", leafHashes.subarray(0, size * 32), size);
      if (out.error !== undefined) throw new Error(`could not hash the tree: ${out.error}`);
      return { root: b64Decode(out.root), interior: out.interior.map((t) => ({ ...t, data: fromHex(t.data) })) };
    },

    async prove(leafHashes, size, index, checkpoint) {
      const out = await ask<{ error?: string; proof?: string }>("tlogProve", leafHashes.subarray(0, size * 32), size, index, checkpoint);
      if (out.error !== undefined || out.proof === undefined) throw new Error(`could not write the proof: ${out.error}`);
      return out.proof;
    },

    async checkProof(policyText, proof, leafHash) {
      const hexHash = [...leafHash].map((b) => b.toString(16).padStart(2, "0")).join("");
      return ask<ProofCheck>("tlogCheckProof", JSON.stringify({ policy: policyText, proof, leafHash: hexHash }));
    },
  };
}

/**
 * Starts the verifier in a worker, given the module the page is compiling
 * (gowasm.ts), and returns the page's handle on it.
 */
export function startVerifier(module: Promise<WebAssembly.Module>): Verifier {
  const worker = new Worker(new URL("./goworker.js", import.meta.url), { type: "module" });
  const pending = new Map<number, { resolve(reply: unknown): void; reject(e: Error): void }>();
  let nextId = 0;
  let broken: Error | null = null;
  const fail = (e: Error) => {
    broken = e;
    for (const p of pending.values()) p.reject(e);
    pending.clear();
  };
  worker.addEventListener("message", (ev: MessageEvent<{ id: number; reply?: unknown; error?: string }>) => {
    // The worker reports a failure to start with no id: nothing can be answered.
    if (ev.data.id < 0) return fail(new Error(ev.data.error ?? "the verifier failed to start"));
    const p = pending.get(ev.data.id);
    if (!p) return;
    pending.delete(ev.data.id);
    if (ev.data.error !== undefined) p.reject(new Error(ev.data.error));
    else p.resolve(ev.data.reply);
  });
  worker.addEventListener("error", (ev) => fail(new Error(`the verifier could not be loaded: ${ev.message || "worker error"}`)));
  module.then(
    (m) => worker.postMessage({ module: m }),
    (e: unknown) => fail(new Error(`the verifier could not be loaded: ${e instanceof Error ? e.message : String(e)}`)));
  return verifierOver((fn, ...args) => new Promise((resolve, reject) => {
    if (broken) return reject(broken);
    const id = nextId++;
    pending.set(id, { resolve, reject });
    worker.postMessage({ id, fn, args });
  }));
}
