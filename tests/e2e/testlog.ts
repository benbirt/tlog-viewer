// A transparency log made up for the browser tests: its own keys, witnesses
// and policy, and entries shaped like the PAIC log's. Built afresh on each
// run, so nothing signed is checked in, and able to grow, fork or misbehave
// on demand, which a recording of the real log could not.

import { b64Encode, type Bytes, concat, hex, sha256, utf8Encode } from "../../web/js/bytes.js";
import type { Call, Verifier } from "../../web/js/verifier.js";
import { loadWasm } from "../../tools/wasm.js";

// The kinds of note key the viewer verifies (tests/signer/main.go).
export const ED25519 = "ed25519";
export const ED25519_COSIGNATURE = "ed25519-cosignature";
export const ML_DSA_44 = "ml-dsa-44";
export type KeyKind = typeof ED25519 | typeof ED25519_COSIGNATURE | typeof ML_DSA_44;

// Keys are made and checkpoints signed by the Go packages the verifier checks
// them with, compiled to WebAssembly from //tests/signer.
let signerModule: Promise<Call> | undefined;
function signer(): Promise<Call> {
  const { SIGNER_WASM: wasm, SIGNER_EXEC: exec } = process.env;
  if (!wasm || !exec) throw new Error("SIGNER_WASM and SIGNER_EXEC must be set");
  return (signerModule ??= loadWasm(wasm, exec, "signer"));
}

async function ask<T>(fn: string, request: unknown, time?: number): Promise<T> {
  const call = await signer();
  // The module does its work before the call returns, and reads the clock
  // through Date, so a cosignature can be given any time by swapping Date
  // for the length of the call.
  const RealDate = Date;
  if (time !== undefined) {
    const ms = time * 1000;
    globalThis.Date = class extends RealDate {
      constructor() {
        super(ms);
      }
      static override now(): number {
        return ms;
      }
    } as DateConstructor;
  }
  let pending: Promise<unknown>;
  try {
    pending = call(fn, JSON.stringify(request));
  } finally {
    globalThis.Date = RealDate;
  }
  const reply = JSON.parse(await pending as string) as T & { error?: string };
  if (reply.error !== undefined) throw new Error(`${fn}: ${reply.error}`);
  return reply;
}

/** A note signing key of one of the three kinds the viewer verifies. */
export class NoteKey {
  private constructor(readonly name: string, readonly kind: KeyKind, readonly vkey: string, private readonly skey: string) {}

  static async generate(name: string, kind: KeyKind): Promise<NoteKey> {
    const { skey, vkey } = await ask<{ skey: string; vkey: string }>("signerKey", { name, kind });
    return new NoteKey(name, kind, vkey, skey);
  }

  /** A signature line for a checkpoint, made at `time` (Unix seconds) where the kind records one. */
  async sign(text: string, time: number): Promise<string> {
    return (await ask<{ line: string }>("signerSign", { skey: this.skey, kind: this.kind, text }, time)).line;
  }
}

const bytes = (b: ArrayBuffer | Uint8Array): Bytes => new Uint8Array(b as ArrayBuffer);

/** An endorser: an ECDSA P-256 key that signs statements. */
class Endorser {
  private constructor(private readonly key: CryptoKey, readonly pemB64: string) {}

  static async generate(): Promise<Endorser> {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    const spki = b64Encode(bytes(await crypto.subtle.exportKey("spki", pair.publicKey)));
    const pem = `-----BEGIN PUBLIC KEY-----\n${spki.replace(/(.{64})/g, "$1\n").trimEnd()}\n-----END PUBLIC KEY-----\n`;
    return new Endorser(pair.privateKey, b64Encode(utf8Encode(pem)));
  }

  /** Signs, returning the signature in the ASN.1 DER form hashedrekord uses. */
  async sign(content: Bytes): Promise<string> {
    const raw = bytes(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.key, content));
    const int = (v: Bytes): number[] => {
      let i = 0;
      while (i < v.length - 1 && v[i] === 0) i++;
      const body = [...v.subarray(i)];
      if (body[0]! & 0x80) body.unshift(0);
      return [0x02, body.length, ...body];
    };
    const seq = [...int(raw.subarray(0, 32)), ...int(raw.subarray(32))];
    return b64Encode(Uint8Array.from([0x30, seq.length, ...seq]));
  }
}

export interface World {
  /** The trust policy naming the test logs and witnesses. */
  policy: string;
  /** A log with entries. */
  main: TestLog;
  /** A witnessed log with no entries. */
  empty: TestLog;
  /** The origin of a log that is in the policy but publishes nothing. */
  unpublished: string;
}

export const PUBLISHERS = ["release-bot@test.example", "other-bot@test.example"];

export class TestLog {
  readonly entries: Bytes[] = [];
  private leafHashes: Bytes = new Uint8Array(0);

  constructor(
    readonly origin: string, private readonly logKeys: NoteKey[],
    private readonly witnesses: NoteKey[], private readonly endorsers: Endorser[],
    /** Lays out and hashes the tree: the page's own verifier, so the fixture is right only if it is. */
    private readonly verifier: Verifier,
  ) {}

  get size(): number {
    return this.entries.length;
  }

  /**
   * Appends endorsements. They are issued a minute apart, the last one a
   * minute ago. Every seventh is valid for a week from thirty days ago, so
   * some have expired; the rest for a year.
   */
  async append(n: number): Promise<void> {
    const now = Date.now();
    for (let k = 0; k < n; k++) {
      const i = this.entries.length;
      const short = i % 7 === 3;
      const issued = new Date(short ? now - 30 * 86400_000 : now - (n - k) * 60_000);
      const until = new Date(issued.getTime() + (short ? 7 : 365) * 86400_000);
      const publisher = PUBLISHERS[i % 5 === 0 ? 1 : 0]!;
      const statement = JSON.stringify({
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://project-oak.github.io/oak/tr/endorsement/v1",
        subject: [{ name: `mpm_${(i * 2654435761 >>> 0).toString(16).padStart(8, "0")}`, digest: { sha256: hex(await sha256(utf8Encode(`artifact ${i}`))) } }],
        predicate: {
          issuedOn: issued.toISOString(),
          validity: { notBefore: issued.toISOString(), notAfter: until.toISOString() },
          claims: [
            { type: "https://github.com/test-org/claims/blob/main/docs/claims/publisher.md", annotations: { publisher_id: publisher } },
            { type: "https://github.com/test-org/claims/blob/main/docs/claims/workload.md", annotations: { workload_id: `workload-${i % 4}`, version: `1.${i}` } },
            { type: "https://github.com/test-org/claims/blob/main/docs/claim/31543.md" },
          ],
        },
      }, null, 2);
      const content = utf8Encode(statement);
      const endorser = this.endorsers[i % 3 === 0 ? 1 : 0]!;
      const record = JSON.stringify({
        apiVersion: "0.0.1",
        kind: "hashedrekord",
        spec: {
          data: { content: b64Encode(content), hash: { algorithm: "sha256", value: hex(await sha256(content)) } },
          signature: { content: await endorser.sign(content), publicKey: { content: endorser.pemB64 } },
        },
      });
      this.entries.push(utf8Encode(record));
    }
    this.leafHashes = concat(...await Promise.all(this.entries.map((e) => this.verifier.leafHash(e))));
  }

  /** A log with the same keys and the first `size` entries, to grow apart from this one. */
  fork(size: number = this.size): TestLog {
    const copy = new TestLog(this.origin, this.logKeys, this.witnesses, this.endorsers, this.verifier);
    copy.entries.push(...this.entries.slice(0, size));
    copy.leafHashes = this.leafHashes.slice(0, size * 32);
    return copy;
  }

  /** Replaces an entry, as a log rewriting its history would. */
  async rewrite(index: number): Promise<void> {
    const record = JSON.parse(Buffer.from(this.entries[index]!).toString());
    record.apiVersion = "0.0.2";
    this.entries[index] = utf8Encode(JSON.stringify(record));
    this.leafHashes = concat(...await Promise.all(this.entries.map((e) => this.verifier.leafHash(e))));
  }

  /**
   * Everything the log serves at its present size, by path: a checkpoint
   * signed and witnessed `age` seconds ago, and the tiles.
   */
  async files(options: { age?: number; witnesses?: number } = {}): Promise<Map<string, Bytes>> {
    const size = this.size;
    const out = new Map<string, Bytes>();
    const { root, interior } = await this.verifier.tree(this.leafHashes, size);
    const layout = await this.verifier.layout(0, size);
    const text = `${this.origin}\n${size}\n${b64Encode(root)}\n`;
    const time = Math.floor(Date.now() / 1000) - (options.age ?? 30);
    const signers = [...this.logKeys, ...this.witnesses.slice(0, options.witnesses ?? this.witnesses.length)];
    const lines = await Promise.all(signers.map((k) => k.sign(text, time)));
    out.set(layout.checkpoint, utf8Encode(text + "\n" + lines.join("")));

    for (const t of layout.tiles) {
      out.set(t.path, this.leafHashes.slice(t.first * 32, (t.first + t.width) * 32));
      out.set(t.entries, concat(...this.entries.slice(t.first, t.first + t.width)
        .flatMap((e) => [Uint8Array.of(e.length >> 8, e.length & 0xff), e])));
    }
    for (const t of interior) out.set(t.path, t.data);
    return out;
  }
}

/**
 * Builds the test logs and their policy. The main log signs with Ed25519 and
 * ML-DSA-44, and the quorum is two of three witnesses, one of them ML-DSA-44,
 * so the tests meet the same mix of algorithms as production.
 */
export async function buildWorld(verifier: Verifier): Promise<World> {
  const main = "test.example/log/0";
  const empty = "test.example/log/1";
  const unpublished = "test.example/log/2";
  const mainKeys = [await NoteKey.generate(main, ED25519), await NoteKey.generate(main, ML_DSA_44)];
  const emptyKey = await NoteKey.generate(empty, ED25519);
  const unpublishedKey = await NoteKey.generate(unpublished, ED25519);
  const witnesses = [
    await NoteKey.generate("one.witness.example", ED25519_COSIGNATURE),
    await NoteKey.generate("two.witness.example", ML_DSA_44),
    await NoteKey.generate("three.witness.example", ED25519_COSIGNATURE),
  ];
  const endorsers = [await Endorser.generate(), await Endorser.generate()];
  const policy = [
    "# A policy for the browser tests.",
    ...[...mainKeys, emptyKey, unpublishedKey].map((k) => `log ${k.vkey}`),
    ...witnesses.map((w, i) => `witness w${i + 1} ${w.vkey} https://${w.name}`),
    "group two-of-three 2 w1 w2 w3",
    "quorum two-of-three",
    "",
  ].join("\n");
  return {
    policy,
    main: new TestLog(main, mainKeys, witnesses, endorsers, verifier),
    empty: new TestLog(empty, [emptyKey], witnesses, endorsers, verifier),
    unpublished,
  };
}
