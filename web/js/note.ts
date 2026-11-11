// Signed notes (https://c2sp.org/signed-note), checkpoints
// (https://c2sp.org/tlog-checkpoint) and cosignatures
// (https://c2sp.org/tlog-cosignature), verified with WebCrypto.

import { b64Decode, type Bytes, concat, fromHex, sha256, uint64be, utf8Encode, view } from "./bytes.js";
import {
  ALG_ED25519, ALG_ED25519_COSIG, ALG_MLDSA44, ALG_NAMES, evaluateQuorum,
  type Policy, type QuorumNode, type VKey,
} from "./policy.js";

const MLDSA44_PUBLIC_KEY_SIZE = 1312;
const MLDSA44_SIGNATURE_SIZE = 2420;
// SubjectPublicKeyInfo header for an ML-DSA-44 key (id-ml-dsa-44, RFC 9881).
const MLDSA44_SPKI_PREFIX = fromHex("30820532300b06096086480165030403110382052100");

export interface NoteSignature {
  name: string;
  keyId: number;
  sig: Bytes;
}

export interface Note {
  /** The signed text, including its final newline. */
  text: string;
  sigs: NoteSignature[];
}

export interface Checkpoint {
  origin: string;
  size: number;
  hash: Bytes;
  extensions: string[];
}

/** "unsupported" means this platform's WebCrypto lacks the algorithm. */
export type VerifyStatus = "valid" | "invalid" | "unsupported";

export interface Verifier {
  name: string;
  keyId: number;
  algName: string;
  /** Whether this platform can verify the key's algorithm at all. */
  supported: boolean;
  /**
   * Whether a signature covers the whole note text. ML-DSA-44 cosignatures
   * sign only the origin, size and root hash, not any extension lines.
   */
  coversText: boolean;
  verify(text: string, checkpoint: Checkpoint, sig: Bytes): Promise<VerifyStatus>;
  /** The cosignature time in Unix seconds; null for untimestamped signatures. */
  timestamp(sig: Bytes): bigint | null;
}

export interface SignatureResult {
  name: string;
  keyId: number;
  role: "log" | "witness" | "unknown";
  /** The policy-local witness name, for witnesses. */
  witness: string | null;
  algName: string | null;
  status: VerifyStatus | "unknown-key";
  /** Unix seconds, for valid timestamped cosignatures. */
  timestamp: bigint | null;
}

export interface CheckpointResult {
  checkpoint: Checkpoint;
  /** The note text the signatures were checked over. */
  text: string;
  signatures: SignatureResult[];
  logSigned: boolean;
  quorum: QuorumNode;
  /**
   * Whether the quorum would be met if the cosignatures this platform cannot
   * check were all valid: distinguishes a browser limitation from a
   * checkpoint that was never witnessed.
   */
  quorumPossible: boolean;
  /**
   * False if the checkpoint has extension lines that no valid log signature
   * covers, so anyone relaying the checkpoint could have altered them.
   */
  extensionsAuthenticated: boolean;
  /** Reasons the checkpoint is rejected. */
  problems: string[];
  /** Anomalies that do not invalidate it, such as a bad signature beside good ones. */
  warnings: string[];
  ok: boolean;
}

/** Splits a signed note into its text and signature lines. */
export function parseNote(raw: string): Note {
  const split = raw.lastIndexOf("\n\n");
  if (split < 0) throw new Error("malformed note: no signature block");
  const text = raw.slice(0, split + 1);
  const sigBlock = raw.slice(split + 2);
  if (!sigBlock.endsWith("\n")) throw new Error("malformed note: missing final newline");
  const sigs: NoteSignature[] = [];
  for (const line of sigBlock.slice(0, -1).split("\n")) {
    // Key names contain no whitespace and no "+".
    const m = /^\u2014 ([^\s+]+) (\S+)$/u.exec(line);
    if (!m) throw new Error("malformed note: bad signature line");
    const bytes = b64Decode(m[2]!);
    if (bytes.length < 5) throw new Error("malformed note: short signature");
    sigs.push({ name: m[1]!, keyId: view(bytes).getUint32(0), sig: bytes.subarray(4) });
  }
  if (sigs.length === 0) throw new Error("malformed note: no signatures");
  return { text, sigs };
}

/** Parses the text of a checkpoint note. */
export function parseCheckpoint(text: string): Checkpoint {
  const lines = text.split("\n");
  const [origin, sizeText, hashText] = lines;
  if (lines.length < 4 || lines.at(-1) !== "" || origin === undefined || sizeText === undefined || hashText === undefined) {
    throw new Error("malformed checkpoint");
  }
  if (origin === "") throw new Error("malformed checkpoint: empty origin");
  if (!/^(0|[1-9][0-9]*)$/.test(sizeText)) throw new Error("malformed checkpoint: bad size");
  const size = Number(sizeText);
  if (!Number.isSafeInteger(size)) throw new Error("malformed checkpoint: size too large");
  const hash = b64Decode(hashText);
  if (hash.length !== 32) throw new Error("malformed checkpoint: bad root hash");
  const extensions = lines.slice(3, -1);
  if (extensions.some((l) => l === "" || /[\x00-\x1f\x7f]/.test(l))) {
    throw new Error("malformed checkpoint: bad extension line");
  }
  return { origin, size, hash, extensions };
}

async function importKey(format: "raw" | "spki", data: Bytes, name: string): Promise<CryptoKey | null> {
  try {
    return await crypto.subtle.importKey(format, data, { name }, false, ["verify"]);
  } catch (e) {
    if (e instanceof Error && e.name === "NotSupportedError") return null;
    throw e;
  }
}

const cosignatureTime = (sig: Bytes): bigint | null => (sig.length >= 8 ? view(sig).getBigUint64(0) : null);

/** Builds a verifier for a vkey, checking that its key ID is the right one. */
export async function newVerifier(vkey: VKey): Promise<Verifier> {
  const { name, keyId, alg, key } = vkey;
  const id = await sha256(concat(utf8Encode(name + "\n"), Uint8Array.of(alg), key));
  if (view(id).getUint32(0) !== keyId) throw new Error(`key id mismatch for ${name}`);
  const base = { name, keyId, algName: ALG_NAMES[alg] ?? `type 0x${alg.toString(16)}` };

  switch (alg) {
    case ALG_ED25519: {
      if (key.length !== 32) throw new Error(`bad Ed25519 key for ${name}`);
      const k = await importKey("raw", key, "Ed25519");
      return {
        ...base,
        supported: k !== null,
        coversText: true,
        timestamp: () => null,
        async verify(text, _checkpoint, sig) {
          if (!k) return "unsupported";
          if (sig.length !== 64) return "invalid";
          const ok = await crypto.subtle.verify({ name: "Ed25519" }, k, sig, utf8Encode(text));
          return ok ? "valid" : "invalid";
        },
      };
    }
    case ALG_ED25519_COSIG: {
      if (key.length !== 32) throw new Error(`bad Ed25519 key for ${name}`);
      const k = await importKey("raw", key, "Ed25519");
      return {
        ...base,
        supported: k !== null,
        coversText: true,
        timestamp: cosignatureTime,
        async verify(text, _checkpoint, sig) {
          if (!k) return "unsupported";
          if (sig.length !== 8 + 64) return "invalid";
          // The time is formatted from the full 64-bit value, not a float.
          const msg = utf8Encode(`cosignature/v1\ntime ${cosignatureTime(sig)}\n${text}`);
          const ok = await crypto.subtle.verify({ name: "Ed25519" }, k, sig.subarray(8), msg);
          return ok ? "valid" : "invalid";
        },
      };
    }
    case ALG_MLDSA44: {
      if (key.length !== MLDSA44_PUBLIC_KEY_SIZE) throw new Error(`bad ML-DSA-44 key for ${name}`);
      const k = await importKey("spki", concat(MLDSA44_SPKI_PREFIX, key), "ML-DSA-44");
      const nameBytes = utf8Encode(name);
      return {
        ...base,
        supported: k !== null,
        coversText: false,
        timestamp: cosignatureTime,
        async verify(_text, checkpoint, sig) {
          if (!k) return "unsupported";
          if (sig.length !== 8 + MLDSA44_SIGNATURE_SIZE) return "invalid";
          const origin = utf8Encode(checkpoint.origin);
          if (nameBytes.length > 255 || origin.length > 255) return "invalid";
          // A checkpoint cosignature is a subtree signature over [0, size).
          const msg = concat(
            utf8Encode("subtree/v1\n\0"),
            Uint8Array.of(nameBytes.length), nameBytes,
            sig.subarray(0, 8),
            Uint8Array.of(origin.length), origin,
            uint64be(0), uint64be(checkpoint.size),
            checkpoint.hash,
          );
          const ok = await crypto.subtle.verify({ name: "ML-DSA-44" }, k, sig.subarray(8), msg);
          return ok ? "valid" : "invalid";
        },
      };
    }
    default:
      return { ...base, supported: false, coversText: false, timestamp: () => null, verify: async () => "unsupported" };
  }
}

/**
 * Applies a policy's checkpoint validity rule to a raw signed checkpoint: it
 * must be signed by one of the policy's logs whose key name is the origin,
 * and cosigned according to the quorum rule. If `expectedOrigin` is given,
 * the checkpoint must also be for that log, so that one log's checkpoint
 * cannot stand in for another's.
 *
 * As in the reference implementation, a signature that fails to verify does
 * not by itself reject a checkpoint that other signatures make valid: a
 * quorum exists to tolerate a faulty witness. Such signatures are reported in
 * `warnings`.
 */
export async function verifyCheckpoint(policy: Policy, raw: string, expectedOrigin?: string): Promise<CheckpointResult> {
  const note = parseNote(raw);
  const checkpoint = parseCheckpoint(note.text);

  type Known = { role: "log" | "witness"; witness: string | null; vkey: VKey };
  const known = new Map<string, Known>();
  const keyOf = (name: string, keyId: number) => `${keyId} ${name}`;
  const add = (k: Known) => {
    const id = keyOf(k.vkey.name, k.vkey.keyId);
    // A key ID is a 32-bit hint, not an identity. Refuse to guess between
    // two policy keys that share a name and an ID.
    if (known.has(id)) throw new Error(`policy has ambiguous keys for ${k.vkey.name}`);
    known.set(id, k);
  };
  for (const log of policy.logs) {
    if (log.vkey.name === checkpoint.origin) add({ role: "log", witness: null, vkey: log.vkey });
  }
  for (const w of policy.witnesses) add({ role: "witness", witness: w.name, vkey: w.vkey });

  const signatures: SignatureResult[] = [];
  const seen = new Set<string>();
  const validWitnesses = new Set<string>();
  const uncheckedWitnesses = new Set<string>();
  const problems: string[] = [];
  const warnings: string[] = [];
  let logSigned = false;
  let textSigned = false;
  for (const s of note.sigs) {
    const id = keyOf(s.name, s.keyId);
    const k = known.get(id);
    const row: SignatureResult = {
      name: s.name, keyId: s.keyId, role: k?.role ?? "unknown", witness: k?.witness ?? null,
      algName: null, status: "unknown-key", timestamp: null,
    };
    signatures.push(row);
    // A checkpoint must not carry two signature lines with the same key
    // name and ID, whether or not the key is one we know.
    if (seen.has(id)) {
      if (k) row.status = "invalid";
      problems.push(`more than one signature line from ${s.name}`);
      continue;
    }
    seen.add(id);
    if (!k) continue;
    const v = await newVerifier(k.vkey);
    row.algName = v.algName;
    row.status = await v.verify(note.text, checkpoint, s.sig);
    if (row.status === "invalid") warnings.push(`invalid signature from ${s.name} (${v.algName})`);
    if (row.status === "unsupported" && k.witness !== null) uncheckedWitnesses.add(k.witness);
    if (row.status !== "valid") continue;
    row.timestamp = v.timestamp(s.sig);
    if (k.role === "log") {
      logSigned = true;
      textSigned ||= v.coversText;
    } else if (k.witness !== null) {
      validWitnesses.add(k.witness);
    }
  }

  if (expectedOrigin !== undefined && checkpoint.origin !== expectedOrigin) {
    problems.push(`checkpoint is for ${checkpoint.origin}, not ${expectedOrigin}`);
  }
  if (!policy.logs.some((l) => l.vkey.name === checkpoint.origin)) {
    problems.push(`origin ${checkpoint.origin} is not a log in the policy`);
  } else if (!logSigned) {
    problems.push("no valid signature from a log key in the policy");
  }
  const quorum = evaluateQuorum(policy, validWitnesses);
  if (!quorum.satisfied) problems.push("witness quorum not met");
  return {
    checkpoint,
    text: note.text,
    signatures,
    logSigned,
    quorum,
    quorumPossible: evaluateQuorum(policy, new Set([...validWitnesses, ...uncheckedWitnesses])).satisfied,
    extensionsAuthenticated: checkpoint.extensions.length === 0 || textSigned,
    problems,
    warnings,
    ok: problems.length === 0,
  };
}
