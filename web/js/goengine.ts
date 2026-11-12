// An alternative checkpoint verifier: the Go implementation
// (github.com/transparency-dev/formats, built by TinyGo from //oracle),
// running in the page as WebAssembly. The policy's verdict and the state of
// every signature come from the Go code; this module only loads it and puts
// its answer in the shape the page displays.
//
// It is a prototype, chosen with engine=go in the address. The default is
// the TypeScript verifier in note.ts.

import { b64Decode } from "./bytes.js";
import { type CheckpointResult, quorumTime, type SignatureResult, type VerifyOptions } from "./note.js";
import { ALG_ED25519, ALG_NAMES, evaluateQuorum, type Policy } from "./policy.js";

/** What the Go code reports about a checkpoint (inspectOut in oracle/main.go). */
export interface Inspection {
  policyError?: string;
  malformed?: string;
  ok: boolean;
  error?: string;
  text: string;
  origin: string;
  size: string;
  hash: string;
  extensions: string[];
  signatures: {
    name: string;
    keyId: number;
    role: "log" | "witness" | "unknown";
    witness?: string;
    alg: number;
    status: "valid" | "invalid" | "unknown-key";
    timestamp?: string;
  }[];
  logSigned: boolean;
  quorum: boolean;
}

/** Calls the Go code's checkpoint inspection with a policy and a signed checkpoint. */
export type Inspect = (policyText: string, checkpoint: string) => Inspection;

/**
 * Turns the Go code's report into the page's result. Two of the page's own
 * rules are applied on top: the checkpoint must be for the expected log, and
 * must not carry two signature lines from one key.
 *
 * The second can only be applied to what Go passes on. Go's note reader drops
 * a signature line that exactly repeats an earlier one before anything sees
 * it, so this engine accepts such a checkpoint where the TypeScript one
 * refuses it. It is likewise as lenient as Go about non-canonical base64 and
 * empty extension lines.
 */
export function resultFromInspection(policy: Policy, out: Inspection, options: VerifyOptions = {}): CheckpointResult {
  if (out.policyError !== undefined) throw new Error(`the Go implementation rejects the trust policy: ${out.policyError}`);
  if (out.malformed !== undefined) throw new Error(`malformed checkpoint: ${out.malformed}`);
  const size = Number(out.size);
  if (!Number.isSafeInteger(size)) throw new Error("malformed checkpoint: size too large");
  const checkpoint = { origin: out.origin, size, hash: b64Decode(out.hash), extensions: out.extensions };

  const problems: string[] = [];
  const warnings: string[] = [];
  const seen = new Set<string>();
  const validWitnesses = new Set<string>();
  const cosignedAt = new Map<string, bigint>();
  let textSigned = false;
  const signatures = out.signatures.map((s): SignatureResult => {
    const id = `${s.keyId} ${s.name}`;
    if (seen.has(id)) problems.push(`more than one signature line from ${s.name}`);
    seen.add(id);
    const algName = s.role === "unknown" ? null : ALG_NAMES[s.alg] ?? `type 0x${s.alg.toString(16)}`;
    const timestamp = s.timestamp !== undefined ? BigInt(s.timestamp) : null;
    if (s.status === "invalid") warnings.push(`invalid signature from ${s.name} (${algName})`);
    if (s.status === "valid" && s.role === "log" && s.alg === ALG_ED25519) textSigned = true;
    if (s.status === "valid" && s.witness !== undefined) {
      validWitnesses.add(s.witness);
      if (timestamp !== null) cosignedAt.set(s.witness, timestamp);
    }
    return { name: s.name, keyId: s.keyId, role: s.role, witness: s.witness ?? null, algName, status: s.status, timestamp };
  });

  // The tree shown for the quorum is worked out here, from the cosignatures Go
  // found valid. Its conclusion must be Go's own.
  const quorum = evaluateQuorum(policy, validWitnesses);
  if (quorum.satisfied !== out.quorum) {
    throw new Error("the page and the Go implementation disagree about the quorum; refusing to show either answer");
  }

  if (options.expectedOrigin !== undefined && out.origin !== options.expectedOrigin) {
    problems.push(`checkpoint is for ${out.origin}, not ${options.expectedOrigin}`);
  }
  if (!policy.logs.some((l) => l.vkey.name === out.origin)) problems.push(`origin ${out.origin} is not a log in the policy`);
  else if (!out.logSigned) problems.push("no valid signature from a log key in the policy");
  if (!quorum.satisfied) problems.push("witness quorum not met");
  // Go's verdict is final: if it says no for a reason not listed above, so does the page.
  if (!out.ok && problems.length === 0) problems.push(`rejected by the Go implementation: ${out.error ?? "no reason given"}`);

  return {
    checkpoint,
    text: out.text,
    signatures,
    logSigned: out.logSigned,
    quorum,
    quorumPossible: quorum.satisfied,
    witnessedAt: quorum.satisfied ? quorumTime(policy, cosignedAt) : null,
    extensionsAuthenticated: out.extensions.length === 0 || textSigned,
    problems,
    warnings,
    ok: out.ok && problems.length === 0,
  };
}

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

let loading: Promise<Inspect> | null = null;

/** Fetches and starts the WebAssembly module, once. */
export function loadGoEngine(): Promise<Inspect> {
  loading ??= (async () => {
    const g = globalThis as unknown as Record<string, unknown>;
    // TinyGo's runtime script defines a global class, Go.
    await import(new URL("../wasm/tinygo_wasm_exec.js", import.meta.url).href);
    const go = new (g.Go as new () => GoRuntime)();
    const { instance } = await WebAssembly.instantiateStreaming(fetch(new URL("../wasm/oracle_tinygo.wasm", import.meta.url)), go.importObject);
    void go.run(instance); // runs for as long as the page uses it
    for (let i = 0; !g.oracleReady; i++) {
      if (i > 500) throw new Error("the Go implementation did not start");
      await new Promise((r) => setTimeout(r, 10));
    }
    const call = g.oracleInspectCheckpoint as (request: string) => string;
    return (policy: string, checkpoint: string) => JSON.parse(call(JSON.stringify({ policy, checkpoint }))) as Inspection;
  })();
  // A failed load may be retried.
  loading.catch(() => { loading = null; });
  return loading;
}

/** verifyCheckpoint, by the Go implementation. */
export async function verifyCheckpointGo(policy: Policy, policyText: string, raw: string, options: VerifyOptions = {}): Promise<CheckpointResult> {
  return resultFromInspection(policy, (await loadGoEngine())(policyText, raw), options);
}
