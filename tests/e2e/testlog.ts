// A transparency log made up for the browser tests: its own keys, witnesses
// and policy, and entries shaped like the PAIC log's. Built afresh on each
// run, so nothing signed is checked in, and able to grow, fork or misbehave
// on demand, which a recording of the real log could not.

import {
  b64Encode, type Bytes, concat, hex, sha256, uint64be, utf8Encode,
} from "../../web/js/bytes.js";
import { interiorTileHashes, leafHash, rootFromLeafHashes } from "../../web/js/merkle.js";
import { ALG_ED25519, ALG_ED25519_COSIG, ALG_MLDSA44 } from "../../web/js/policy.js";
import { TILE_WIDTH, tilePath, tilesForSize } from "../../web/js/tiles.js";

const bytes = (b: ArrayBuffer | Uint8Array): Bytes => new Uint8Array(b as ArrayBuffer);

/** A note signing key of one of the three kinds the viewer verifies. */
export class NoteKey {
  private constructor(
    readonly name: string, readonly alg: number, readonly publicKey: Bytes,
    readonly keyId: Bytes, private readonly key: CryptoKey,
  ) {}

  static async generate(name: string, alg: number): Promise<NoteKey> {
    const algorithm = alg === ALG_MLDSA44 ? "ML-DSA-44" : "Ed25519";
    const pair = await crypto.subtle.generateKey({ name: algorithm }, true, ["sign", "verify"]) as CryptoKeyPair;
    // The raw key is the tail of its SubjectPublicKeyInfo.
    const spki = bytes(await crypto.subtle.exportKey("spki", pair.publicKey));
    const publicKey = spki.slice(spki.length - (alg === ALG_MLDSA44 ? 1312 : 32));
    const id = (await sha256(concat(utf8Encode(name + "\n"), Uint8Array.of(alg), publicKey))).slice(0, 4);
    return new NoteKey(name, alg, publicKey, id, pair.privateKey);
  }

  get vkey(): string {
    return `${this.name}+${hex(this.keyId)}+${b64Encode(concat(Uint8Array.of(this.alg), this.publicKey))}`;
  }

  /** A signature line for a checkpoint, made at `time` (Unix seconds) where the kind records one. */
  async sign(cp: { origin: string; size: number; root: Bytes; text: string }, time: number): Promise<string> {
    let sig: Bytes;
    if (this.alg === ALG_ED25519) {
      sig = bytes(await crypto.subtle.sign({ name: "Ed25519" }, this.key, utf8Encode(cp.text)));
    } else if (this.alg === ALG_ED25519_COSIG) {
      const msg = utf8Encode(`cosignature/v1\ntime ${time}\n${cp.text}`);
      sig = concat(uint64be(time), bytes(await crypto.subtle.sign({ name: "Ed25519" }, this.key, msg)));
    } else {
      const name = utf8Encode(this.name);
      const origin = utf8Encode(cp.origin);
      const msg = concat(
        utf8Encode("subtree/v1\n\0"), Uint8Array.of(name.length), name, uint64be(time),
        Uint8Array.of(origin.length), origin, uint64be(0), uint64be(cp.size), cp.root);
      sig = concat(uint64be(time), bytes(await crypto.subtle.sign({ name: "ML-DSA-44" }, this.key, msg)));
    }
    return `— ${this.name} ${b64Encode(concat(this.keyId, sig))}\n`;
  }
}

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
    this.leafHashes = concat(...await Promise.all(this.entries.map((e) => leafHash(e))));
  }

  /** A log with the same keys and the first `size` entries, to grow apart from this one. */
  fork(size: number = this.size): TestLog {
    const copy = new TestLog(this.origin, this.logKeys, this.witnesses, this.endorsers);
    copy.entries.push(...this.entries.slice(0, size));
    copy.leafHashes = this.leafHashes.slice(0, size * 32);
    return copy;
  }

  /** Replaces an entry, as a log rewriting its history would. */
  async rewrite(index: number): Promise<void> {
    const record = JSON.parse(Buffer.from(this.entries[index]!).toString());
    record.apiVersion = "0.0.2";
    this.entries[index] = utf8Encode(JSON.stringify(record));
    this.leafHashes = concat(...await Promise.all(this.entries.map((e) => leafHash(e))));
  }

  /**
   * Everything the log serves at its present size, by path: a checkpoint
   * signed and witnessed `age` seconds ago, and the tiles.
   */
  async files(options: { age?: number; witnesses?: number } = {}): Promise<Map<string, Bytes>> {
    const size = this.size;
    const out = new Map<string, Bytes>();
    const root = await rootFromLeafHashes(this.leafHashes, size);
    const text = `${this.origin}\n${size}\n${b64Encode(root)}\n`;
    const time = Math.floor(Date.now() / 1000) - (options.age ?? 30);
    const signers = [...this.logKeys, ...this.witnesses.slice(0, options.witnesses ?? this.witnesses.length)];
    const lines = await Promise.all(signers.map((k) => k.sign({ origin: this.origin, size, root, text }, time)));
    out.set("checkpoint", utf8Encode(text + "\n" + lines.join("")));

    for (const t of tilesForSize(size)) {
      const start = t.index * TILE_WIDTH;
      out.set(tilePath(0, t.index, t.width), this.leafHashes.slice(start * 32, (start + t.width) * 32));
      out.set(tilePath("entries", t.index, t.width), concat(...this.entries.slice(start, start + t.width)
        .flatMap((e) => [Uint8Array.of(e.length >> 8, e.length & 0xff), e])));
    }
    for (const [i, hashes] of (await interiorTileHashes(this.leafHashes, size)).entries()) {
      for (const t of tilesForSize(hashes.length / 32)) {
        out.set(tilePath(i + 1, t.index, t.width), hashes.slice(t.index * TILE_WIDTH * 32, (t.index * TILE_WIDTH + t.width) * 32));
      }
    }
    return out;
  }
}

/**
 * Builds the test logs and their policy. The main log signs with Ed25519 and
 * ML-DSA-44, and the quorum is two of three witnesses, one of them ML-DSA-44,
 * so the tests meet the same mix of algorithms as production.
 */
export async function buildWorld(): Promise<World> {
  const main = "test.example/log/0";
  const empty = "test.example/log/1";
  const unpublished = "test.example/log/2";
  const mainKeys = [await NoteKey.generate(main, ALG_ED25519), await NoteKey.generate(main, ALG_MLDSA44)];
  const emptyKey = await NoteKey.generate(empty, ALG_ED25519);
  const unpublishedKey = await NoteKey.generate(unpublished, ALG_ED25519);
  const witnesses = [
    await NoteKey.generate("one.witness.example", ALG_ED25519_COSIG),
    await NoteKey.generate("two.witness.example", ALG_MLDSA44),
    await NoteKey.generate("three.witness.example", ALG_ED25519_COSIG),
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
    main: new TestLog(main, mainKeys, witnesses, endorsers),
    empty: new TestLog(empty, [emptyKey], witnesses, endorsers),
    unpublished,
  };
}
