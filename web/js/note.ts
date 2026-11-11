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
  verify(text: string, checkpoint: Checkpoint, sig: Bytes): Promise<VerifyStatus>;
  /** The cosignature time in Unix seconds; null for untimestamped signatures. */
  timestamp(sig: Bytes): number | null;
}

export interface SignatureResult {
  name: string;
  keyId: number;
  role: "log" | "witness" | "unknown";
  /** The policy-local witness name, for witnesses. */
  witness: string | null;
  algName: string | null;
  status: VerifyStatus | "unknown-key";
  timestamp: number | null;
}

export interface CheckpointResult {
  checkpoint: Checkpoint;
  signatures: SignatureResult[];
  logSigned: boolean;
  quorum: QuorumNode;
  problems: string[];
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
    const m = /^— (\S+) (\S+)$/.exec(line);
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
  return { origin, size, hash, extensions: lines.slice(3, -1) };
}

async function importKey(format: "raw" | "spki", data: Bytes, name: string): Promise<CryptoKey | null> {
  try {
    return await crypto.subtle.importKey(format, data, { name }, false, ["verify"]);
  } catch (e) {
    if (e instanceof Error && e.name === "NotSupportedError") return null;
    throw e;
  }
}

const cosignatureTime = (sig: Bytes): number | null => (sig.length >= 8 ? Number(view(sig).getBigUint64(0)) : null);

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
        timestamp: cosignatureTime,
        async verify(text, _checkpoint, sig) {
          if (!k) return "unsupported";
          if (sig.length !== 8 + 64) return "invalid";
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
      return { ...base, timestamp: () => null, verify: async () => "unsupported" };
  }
}

/**
 * Applies a policy's checkpoint validity rule to a raw signed checkpoint:
 * signed by one of the policy's logs whose key name is the origin, and
 * cosigned according to the quorum rule.
 */
export async function verifyCheckpoint(policy: Policy, raw: string): Promise<CheckpointResult> {
  const note = parseNote(raw);
  const checkpoint = parseCheckpoint(note.text);

  type Known = { role: "log" | "witness"; witness: string | null; vkey: VKey };
  const known = new Map<string, Known>();
  const keyOf = (name: string, keyId: number) => `${keyId} ${name}`;
  for (const log of policy.logs) {
    if (log.vkey.name !== checkpoint.origin) continue;
    known.set(keyOf(log.vkey.name, log.vkey.keyId), { role: "log", witness: null, vkey: log.vkey });
  }
  for (const w of policy.witnesses) {
    known.set(keyOf(w.vkey.name, w.vkey.keyId), { role: "witness", witness: w.name, vkey: w.vkey });
  }

  const signatures: SignatureResult[] = [];
  const seen = new Set<string>();
  const validWitnesses = new Set<string>();
  const problems: string[] = [];
  let logSigned = false;
  for (const s of note.sigs) {
    const id = keyOf(s.name, s.keyId);
    const k = known.get(id);
    const row: SignatureResult = {
      name: s.name, keyId: s.keyId, role: k?.role ?? "unknown", witness: k?.witness ?? null,
      algName: null, status: "unknown-key", timestamp: null,
    };
    signatures.push(row);
    if (!k) continue;
    if (seen.has(id)) {
      row.status = "invalid";
      problems.push(`duplicate signature from ${s.name}`);
      continue;
    }
    seen.add(id);
    const v = await newVerifier(k.vkey);
    row.algName = v.algName;
    row.status = await v.verify(note.text, checkpoint, s.sig);
    if (row.status === "invalid") problems.push(`invalid signature from ${s.name} (${v.algName})`);
    if (row.status !== "valid") continue;
    row.timestamp = v.timestamp(s.sig);
    if (k.role === "log") logSigned = true;
    else if (k.witness !== null) validWitnesses.add(k.witness);
  }

  if (!policy.logs.some((l) => l.vkey.name === checkpoint.origin)) {
    problems.push(`origin ${checkpoint.origin} is not a log in the policy`);
  } else if (!logSigned) {
    problems.push("no valid signature from a log key in the policy");
  }
  const quorum = evaluateQuorum(policy, validWitnesses);
  if (!quorum.satisfied) problems.push("witness quorum not met");
  return { checkpoint, signatures, logSigned, quorum, problems, ok: problems.length === 0 };
}
