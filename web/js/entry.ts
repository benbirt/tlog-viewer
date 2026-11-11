// PAIC log entries: hashedrekord JSON whose spec.data.content (an extension
// to the stock hashedrekord schema) carries a base64 in-toto Statement with a
// Project Oak endorsement predicate.

import { b64Decode, type Bytes, hex, sha256, utf8Decode } from "./bytes.js";

export interface Claim {
  type: string;
  annotations: Record<string, unknown> | null;
}

/** The fields of an endorsement statement that the viewer displays. */
export interface Summary {
  type: string | null;
  predicateType: string | null;
  subjectName: string | null;
  subjectDigest: string | null;
  subjectCount: number;
  issuedOn: string | null;
  notBefore: string | null;
  notAfter: string | null;
  claims: Claim[];
  publisher: string | null;
  workload: string | null;
  version: string | null;
  artifact: string | null;
}

export interface DecodedEntry {
  /** The entry as logged, if it is text. */
  recordText: string | null;
  statement: unknown;
  summary: Summary | null;
  statementText: string | null;
  keyPem: string | null;
  /** SHA-256 of the signing key's SubjectPublicKeyInfo, in hex. */
  keyFingerprint: string | null;
  /**
   * Each check is true, false, or null if it could not be made: no SHA-256
   * digest is recorded, the key is of a kind this viewer does not verify, or
   * the entry could not be decoded far enough to try.
   */
  checks: { contentHash: boolean | null; signature: boolean | null };
  /** Why the entry or its statement could not be decoded, if so. */
  error: string | null;
  /** Why the signing key could not be read, if so. */
  keyError: string | null;
}

interface LoadedKey {
  pem: string;
  fingerprint: string;
  /** Null unless the key is ECDSA P-256. */
  key: CryptoKey | null;
}

const keyCache = new Map<string, Promise<LoadedKey>>();

function pemToDer(pem: string): Bytes {
  const m = /^-----BEGIN PUBLIC KEY-----\r?\n([A-Za-z0-9+\/=\r\n]+)-----END PUBLIC KEY-----(\r?\n)?$/.exec(pem);
  if (!m) throw new Error("not a PEM public key");
  return b64Decode(m[1]!.replace(/[\r\n]/g, ""));
}

/** Loads a base64(PEM SubjectPublicKeyInfo) key. */
function loadKey(b64Pem: string): Promise<LoadedKey> {
  let p = keyCache.get(b64Pem);
  if (!p) {
    p = (async () => {
      const pem = utf8Decode(b64Decode(b64Pem));
      const der = pemToDer(pem);
      const fingerprint = hex(await sha256(der));
      let key: CryptoKey | null = null;
      try {
        key = await crypto.subtle.importKey("spki", der, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
      } catch {
        // Not a P-256 key; the signature is reported as unverifiable.
      }
      return { pem, fingerprint, key };
    })();
    keyCache.set(b64Pem, p);
  }
  return p;
}

/**
 * Converts an ASN.1 DER ECDSA-Sig-Value to the r||s form WebCrypto wants.
 * Only strict DER is accepted, as by the Go and OpenSSL verifiers: short-form
 * lengths, and positive integers with no more leading zeros than their sign
 * needs. `size` is the byte length of the curve order, at most 61 so that
 * every length fits the short form.
 */
export function derSignatureToRaw(der: Bytes, size: number = 32): Bytes {
  let p = 0;
  const byte = (): number => {
    const b = der[p++];
    if (b === undefined) throw new Error("truncated DER");
    return b;
  };
  const readLen = (): number => {
    const len = byte();
    if (len & 0x80) throw new Error("DER length is not in short form");
    return len;
  };
  if (byte() !== 0x30) throw new Error("bad DER signature");
  const seqLen = readLen();
  if (p + seqLen !== der.length) throw new Error("bad DER signature length");
  const out = new Uint8Array(size * 2);
  for (let i = 0; i < 2; i++) {
    if (byte() !== 0x02) throw new Error("bad DER integer");
    const len = readLen();
    let v = der.subarray(p, p + len);
    if (len === 0 || v.length !== len) throw new Error("truncated DER integer");
    p += len;
    if (v[0]! & 0x80) throw new Error("negative DER integer");
    if (v[0] === 0 && v.length > 1) {
      if (!(v[1]! & 0x80)) throw new Error("DER integer is not minimal");
      v = v.subarray(1);
    }
    if (v.length > size) throw new Error("DER integer too large");
    out.set(v, size * (i + 1) - v.length);
  }
  if (p !== der.length) throw new Error("trailing DER data");
  return out;
}

// Log entries are untrusted JSON: read them without assuming any shape.
type Json = Record<string, unknown>;
const obj = (v: unknown): Json => (typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Json) : {});
const arr = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);

export function summariseStatement(statement: unknown): Summary {
  const st = obj(statement);
  const subjects = arr(st.subject);
  const subject = obj(subjects[0]);
  const pred = obj(st.predicate);
  const validity = obj(pred.validity);
  const claims: Claim[] = arr(pred.claims).map((c) => {
    const claim = obj(c);
    return {
      type: str(claim.type) ?? "",
      annotations: typeof claim.annotations === "object" && claim.annotations !== null ? obj(claim.annotations) : null,
    };
  });
  const annotation = (k: string): string | null => {
    for (const c of claims) {
      const v = str(c.annotations?.[k]);
      if (v !== null) return v;
    }
    return null;
  };
  return {
    type: str(st._type),
    predicateType: str(st.predicateType),
    subjectName: str(subject.name),
    subjectDigest: str(obj(subject.digest).sha256),
    subjectCount: subjects.length,
    issuedOn: str(pred.issuedOn),
    notBefore: str(validity.notBefore),
    notAfter: str(validity.notAfter),
    claims,
    publisher: annotation("publisher_id"),
    workload: annotation("workload_id"),
    version: annotation("version"),
    artifact: annotation("artifact_id"),
  };
}

/**
 * Decodes one log entry and checks what the entry asserts about itself:
 * that spec.data.hash is the SHA-256 of the content, and that the signature
 * over the content verifies under the embedded public key.
 *
 * Never throws: failures are reported in `error`, `keyError` and `checks`.
 * Each part is decoded independently, so that a bad key does not hide the
 * statement from someone inspecting what was logged.
 */
export async function decodeEntry(bytes: Bytes): Promise<DecodedEntry> {
  const out: DecodedEntry = {
    recordText: null, statement: null, summary: null, statementText: null,
    keyPem: null, keyFingerprint: null,
    checks: { contentHash: null, signature: null },
    error: null, keyError: null,
  };
  const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

  let content: Bytes;
  let signature: Json;
  try {
    out.recordText = utf8Decode(bytes);
    const record = obj(JSON.parse(out.recordText));
    if (record.kind !== "hashedrekord") throw new Error(`unexpected entry kind ${String(record.kind)}`);
    const spec = obj(record.spec);
    const data = obj(spec.data);
    signature = obj(spec.signature);
    const contentB64 = str(data.content);
    if (contentB64 === null) throw new Error("entry has no spec.data.content");
    content = b64Decode(contentB64);

    const hash = obj(data.hash);
    if (hash.algorithm === "sha256") {
      out.checks.contentHash = hex(await sha256(content)) === hash.value;
    }
  } catch (e) {
    out.error = message(e);
    return out;
  }

  try {
    out.statementText = utf8Decode(content);
    out.statement = JSON.parse(out.statementText);
    out.summary = summariseStatement(out.statement);
  } catch (e) {
    out.error = `statement: ${message(e)}`;
  }

  try {
    const loaded = await loadKey(str(obj(signature.publicKey).content) ?? "");
    out.keyPem = loaded.pem;
    out.keyFingerprint = loaded.fingerprint;
    if (loaded.key) {
      try {
        const raw = derSignatureToRaw(b64Decode(str(signature.content) ?? ""));
        out.checks.signature = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, loaded.key, raw, content);
      } catch {
        out.checks.signature = false;
      }
    }
  } catch (e) {
    // With no readable key there is nothing the signature could verify under.
    out.keyError = message(e);
    out.checks.signature = false;
  }
  return out;
}
