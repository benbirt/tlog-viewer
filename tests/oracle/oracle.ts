// Loads the WebAssembly oracle (//oracle): the Go implementations of the
// transparency formats, which the tests compare the TypeScript verifier with.
// Which build to load, Go's or TinyGo's, comes from the environment.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { type Bytes, hex } from "../../web/js/bytes.js";
import type { Inspect } from "../../web/js/goengine.js";

export interface OraclePolicy {
  error?: string;
  logs: string[];
  witnesses: { name: string; vkey: string }[];
  groups: { name: string; threshold: number; members: string[] }[];
  quorum: string;
}

export interface OracleCheckpoint {
  policyError?: string;
  /** The policy's verdict: signed by one of its logs and cosigned to its quorum. */
  ok: boolean;
  error?: string;
  origin?: string;
  size: number;
  hash?: string;
  logSigned: boolean;
  quorum: boolean;
  /** Policy names of the witnesses with a valid cosignature, sorted. */
  witnesses: string[];
}

export interface OracleProof {
  error?: string;
  index: number;
  hashes: string[];
  checkpoint: string;
}

export interface Oracle {
  /** "go" or "tinygo". */
  variant: string;
  parsePolicy(text: string): OraclePolicy;
  verifyCheckpoint(policy: string, checkpoint: string): OracleCheckpoint;
  /** What the page's Go engine is given: the verdict and every signature line (goengine.ts). */
  inspectCheckpoint: Inspect;
  parseProof(text: string): OracleProof;
  formatProof(proof: { index: number; hashes: string[]; checkpoint: string }): string;
  /** The tree head of the first `size` leaf hashes and, for index >= 0, that leaf's inclusion proof. */
  tree(leafHashes: Bytes, size: number, index: number): { error?: string; root: string; proof: string[] };
}

type Call = (request: string) => string;

export async function loadOracle(): Promise<Oracle> {
  const { ORACLE_WASM: wasm, ORACLE_EXEC: exec, ORACLE_VARIANT: variant } = process.env;
  if (!wasm || !exec || !variant) throw new Error("ORACLE_WASM, ORACLE_EXEC and ORACLE_VARIANT must be set");
  // Go's and TinyGo's runtime scripts each define a global class, Go.
  await import(pathToFileURL(resolve(exec)).href);
  const g = globalThis as unknown as Record<string, unknown>;
  const go = new (g.Go as new () => { importObject: WebAssembly.Imports; run(instance: WebAssembly.Instance): Promise<void> })();
  const { instance } = await WebAssembly.instantiate(readFileSync(resolve(wasm)), go.importObject);
  void go.run(instance); // runs for as long as the module serves calls
  for (let i = 0; !g.oracleReady; i++) {
    if (i > 500) throw new Error("the oracle did not start");
    await new Promise((r) => setTimeout(r, 10));
  }
  const call = <T>(name: string, request: unknown): T => JSON.parse((g[name] as Call)(JSON.stringify(request))) as T;
  return {
    variant,
    parsePolicy: (text) => call("oracleParsePolicy", text),
    verifyCheckpoint: (policy, checkpoint) => call("oracleVerifyCheckpoint", { policy, checkpoint }),
    inspectCheckpoint: (policy, checkpoint) => call("oracleInspectCheckpoint", { policy, checkpoint }),
    parseProof: (text) => call("oracleParseProof", text),
    formatProof: (proof) => call("oracleFormatProof", proof),
    tree: (leafHashes, size, index) => call("oracleTree", { leaves: hex(leafHashes.subarray(0, size * 32)), size, index }),
  };
}
