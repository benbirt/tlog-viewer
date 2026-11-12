// The verifier is built twice from the same Go source: by TinyGo, which is
// what the site ships, and by the Go compiler. TinyGo has its own runtime,
// its own reflection and its own builds of parts of the standard library, so
// the build the page runs is held here to the reference compiler's: on valid
// input, on hand-made awkward input and on thousands of mutations of both,
// the two must give the same answer, byte for byte.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";
import { b64Encode, type Bytes, sha256, utf8Encode } from "../../web/js/bytes.js";
import { POLICY_TEXT } from "../../web/js/policy_data.js";
import type { Call } from "../../web/js/verifier.js";
import { loadWasm } from "../../tools/wasm.js";
import { ED25519, ED25519_COSIGNATURE, ML_DSA_44, NoteKey } from "../e2e/testlog.js";

const testdata = (f: string) => readFileSync(new URL("../testdata/" + f, import.meta.url));
const POLICY = testdata("prod-verifier-668ba3c.policy").toString();
const CHECKPOINT = testdata("checkpoint-5522.txt").toString();

let go: Call;
let tinygo: Call;
before(async () => {
  const env = (name: string) => process.env[name] ?? assert.fail(`${name} must be set`);
  go = await loadWasm(env("VERIFIER_GO_WASM"), env("VERIFIER_GO_EXEC"));
  tinygo = await loadWasm(env("VERIFIER_TINYGO_WASM"), env("VERIFIER_TINYGO_EXEC"));
});

/** Asks both builds the same question, insists on the same answer, and returns it. */
async function both<T>(fn: string, ...args: unknown[]): Promise<T> {
  const [x, y] = [await go(fn, ...args), await tinygo(fn, ...args)];
  // Most replies are JSON; bytes are compared as hex.
  const text = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v, (_k, b: unknown) => (b instanceof Uint8Array ? Buffer.from(b).toString("hex") : b)));
  const [a, b] = [text(x), text(y)];
  if (a !== b) {
    const input = args.map((x) => (typeof x === "string" ? x : `<${String(x).slice(0, 40)}>`)).join(", ");
    assert.fail(`${fn}: the builds disagree\n  go:     ${a.slice(0, 600)}\n  tinygo: ${b.slice(0, 600)}\n  input:  ${input.slice(0, 600)}`);
  }
  return (typeof x === "string" ? JSON.parse(x) : x) as T;
}

// ---------------------------------------------------------------------------
// Generating input

/** A small seeded generator, so that a failure can be reproduced. */
function random(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const int = (r: () => number, n: number) => Math.floor(r() * n);
const pick = <T>(r: () => number, items: readonly T[]): T => items[int(r, items.length)]!;

/** Characters worth trying anywhere in a text format. */
const AWKWARD = [" ", "\t", "\n", "\r", "\0", "+", "=", "#", "/", "A", "0", "9", "z", "—", " ", "é", ""];

/** One random small change to a text: a character replaced, inserted, removed or doubled. */
function mutateText(r: () => number, text: string): string {
  const i = int(r, text.length + 1);
  switch (int(r, 4)) {
    case 0: return text.slice(0, i) + pick(r, AWKWARD) + text.slice(i + 1);
    case 1: return text.slice(0, i) + pick(r, AWKWARD) + text.slice(i);
    case 2: return text.slice(0, i) + text.slice(i + 1);
    default: return text.slice(0, i) + text.slice(i - 1, i) + text.slice(i);
  }
}

/** One random change to a line-based text: a line dropped, repeated, moved, or a word of it changed. */
function mutateLines(r: () => number, text: string): string {
  const lines = text.split("\n");
  const i = int(r, lines.length);
  const j = int(r, lines.length);
  switch (int(r, 5)) {
    case 0: lines.splice(i, 1); break;
    case 1: lines.splice(j, 0, lines[i]!); break;
    case 2: [lines[i], lines[j]] = [lines[j]!, lines[i]!]; break;
    case 3: {
      const words = lines[i]!.split(" ");
      const others = lines[j]!.split(" ");
      words[int(r, words.length)] = pick(r, [...others, "any", "all", "0", "1", "2", "99", "none", ""]);
      lines[i] = words.join(" ");
      break;
    }
    default: lines[i] = mutateText(r, lines[i]!); break;
  }
  return lines.join("\n");
}

/** Replaces the base64 of one signature line with an edited copy of its bytes. */
function editSignature(checkpoint: string, line: number, edit: (sig: Buffer) => Buffer | void): string {
  const split = checkpoint.lastIndexOf("\n\n");
  const lines = checkpoint.slice(split + 2).split("\n").filter((l) => l !== "");
  const m = /^(— \S+) (\S+)$/.exec(lines[line]!)!;
  const bytes = Buffer.from(m[2]!, "base64");
  lines[line] = `${m[1]} ${(edit(bytes) ?? bytes).toString("base64")}`;
  return checkpoint.slice(0, split + 2) + lines.map((l) => l + "\n").join("");
}

// ---------------------------------------------------------------------------
// Policies

/** Policies written to probe particular rules, built around one real witness and one real log key. */
function handMadePolicies(): string[] {
  const lines = POLICY.split("\n");
  const log = lines.find((l) => l.startsWith("log "))!;
  const witness = lines.find((l) => l.startsWith("witness cloudflare-ed25519 "))!;
  const [, , vkey, url] = witness.split(" ");
  const logVkey = log.split(" ")[1]!;
  const w = (name: string, key = vkey, ...rest: string[]) => ["witness", name, key, ...rest].join(" ");
  const other = lines.find((l) => l.startsWith("witness glasklar-g1-01-ed25519 "))!.split(" ")[2]!;
  const [name, id, key] = [vkey!.split("+")[0]!, vkey!.split("+")[1]!, vkey!.split("+").slice(2).join("+")];
  return [
    "", "\n", "quorum none\n", "quorum none", "quorum\n", "quorum none none\n", "quorum none\nquorum none\n",
    `${log}\nquorum none\n`, `${log}\n${log}\nquorum none\n`, `log\nquorum none\n`, `log ${logVkey} https://example.com extra\nquorum none\n`,
    `log ${logVkey} https://example.com/log\nquorum none\n`, `log ${logVkey} not-a-url\nquorum none\n`,
    `${w("a")}\nquorum a\n`, `${w("a")}\nquorum b\n`, `${w("a")}\n`, `quorum a\n${w("a")}\n`,
    `${w("a")}\n${w("a", other)}\nquorum a\n`, `${w("a")}\n${w("b")}\nquorum a\n`,
    `${w("a")}\n${w("b", other)}\ngroup g 2 a b\nquorum g\n`, `${w("a")}\n${w("b", other)}\ngroup g 3 a b\nquorum g\n`,
    `${w("a")}\ngroup g 0 a\nquorum g\n`, `${w("a")}\ngroup g -1 a\nquorum g\n`, `${w("a")}\ngroup g 01 a\nquorum g\n`,
    `${w("a")}\ngroup g 1.0 a\nquorum g\n`, `${w("a")}\ngroup g +1 a\nquorum g\n`, `${w("a")}\ngroup g 1 a a\nquorum g\n`,
    `${w("a")}\ngroup g any a\nquorum g\n`, `${w("a")}\ngroup g all a\nquorum g\n`, `${w("a")}\ngroup g ANY a\nquorum g\n`,
    `${w("a")}\ngroup g any\nquorum g\n`, `${w("a")}\ngroup g\nquorum g\n`, `${w("a")}\ngroup a any a\nquorum a\n`,
    `${w("a")}\ngroup g any a\ngroup g any a\nquorum g\n`, `${w("a")}\ngroup g any a\ngroup h any a\nquorum h\n`,
    `${w("a")}\n${w("b", other)}\ngroup g any a b\ngroup h all g b\nquorum h\n`, `${w("a")}\ngroup g 0000000000000000001 a\nquorum g\n`,
    `${w("a", vkey, "https://example.com/%zz")}\nquorum a\n`, `${w("a", vkey, "/relative")}\nquorum a\n`, `${w("a", vkey, "http://[::1")}\nquorum a\n`, `${w("a")}\ngroup g any a\ngroup h any g\nquorum h\n`,
    `${w("a")}\ngroup h any g\ngroup g any a\nquorum h\n`, `${w("a")}\ngroup g any g\nquorum g\n`,
    `${w("none")}\nquorum none\n`, `${w("a")}\ngroup none any a\nquorum none\n`, `${w("any")}\ngroup all any any\nquorum all\n`,
    `${w("quorum")}\ngroup group any quorum\nquorum group\n`, `${w("a")}\ngroup g 99999999999999999999 a\nquorum g\n`,
    `${w("a", vkey, url!)}\nquorum a\n`, `${w("a", vkey, url!, "extra")}\nquorum a\n`, `witness a\nquorum a\n`, `witness\nquorum none\n`,
    `  ${w("a")}\nquorum a\n`, `${w("a")}  \nquorum a\n`, `\t${w("a")}\t\nquorum\ta\n`, `${w("a").replaceAll(" ", "  ")}\nquorum  a\n`,
    `${w("a")}\r\nquorum a\r\n`, `${w("a")}\nquorum a\n\n\n`, `\n\n${w("a")}\n\nquorum a`, `${w("a")}\nquorum a\n\0`,
    `# comment\n${w("a")}\n  # indented\n\t#tab\n#\nquorum a\n`, `${w("a")} # trailing\nquorum a\n`, `${w("a")}\nquorum a # trailing\n`,
    `${w("a")}\n#quorum b\nquorum a\n`, `Witness a ${vkey}\nquorum a\n`, `${w("a")}\nQUORUM a\n`, `frobnicate\nquorum none\n`,
    `${w("a", `${name}+${id}+${key.slice(0, -4)}`)}\nquorum a\n`, `${w("a", `${name}+${id}+${key}AAAA`)}\nquorum a\n`,
    `${w("a", `${name}+00000000+${key}`)}\nquorum a\n`, `${w("a", `${name}+${id.toUpperCase()}+${key}`)}\nquorum a\n`,
    `${w("a", `${name}+${id.slice(1)}+${key}`)}\nquorum a\n`, `${w("a", `${name}+0${id}+${key}`)}\nquorum a\n`,
    `${w("a", `other.example+${id}+${key}`)}\nquorum a\n`, `${w("a", `+${id}+${key}`)}\nquorum a\n`, `${w("a", `${name}++${key}`)}\nquorum a\n`,
    `${w("a", `${name}+${id}`)}\nquorum a\n`, `${w("a", `${name}+${id}+`)}\nquorum a\n`, `${w("a", name)}\nquorum a\n`,
    `${w("a", `${name}+${id}+${key.replace(/=*$/, "")}`)}\nquorum a\n`, `${w("a", `${name}+${id}+${key.replaceAll("+", "-").replaceAll("/", "_")}`)}\nquorum a\n`,
    // A log's key offered as a witness, and a witness's as a log.
    `${w("a", logVkey)}\nquorum a\n`, `log ${vkey}\nquorum none\n`, `log ${vkey}\n${w("a")}\nquorum a\n`,
    `${w("é")}\nquorum é\n`, `${w("a b")}\nquorum a b\n`, `${w("a+b")}\nquorum a+b\n`, `${w("#a")}\nquorum #a\n`,
  ];
}

test("the builds read policies alike", async () => {
  let accepted = 0;
  const cases = [POLICY, POLICY_TEXT, ...handMadePolicies()];
  const r = random(1);
  // A shorter policy keeps mutations from landing mostly in key material.
  const small = POLICY.split("\n").filter((l) => !l.startsWith("#") && l !== "").filter((l, i) => i < 3 || !l.startsWith("log ")).join("\n") + "\n";
  for (let i = 0; i < 1500; i++) {
    let text = pick(r, [POLICY, small, small]);
    for (let n = 1 + int(r, 3); n > 0; n--) text = r() < 0.6 ? mutateLines(r, text) : mutateText(r, text);
    cases.push(text);
  }
  for (const text of cases) {
    if ((await both<{ error?: string }>("tlogPolicy", JSON.stringify(text))).error === undefined) accepted++;
  }
  console.log(`policies: ${cases.length} read alike, ${accepted} of them accepted`);
  // Both verdicts must be well represented for agreement to mean anything.
  assert.ok(accepted > 100 && cases.length - accepted > 100);
});

// ---------------------------------------------------------------------------
// Checkpoints

interface Verdict { malformed?: string; ok: boolean }

/** Judges checkpoints under policies with both builds, and counts the verdicts. */
class Verdicts {
  ok = 0;
  refused = 0;
  malformed = 0;

  async judge(policy: string, checkpoint: string, expectedOrigin: string): Promise<void> {
    const v = await both<Verdict>("tlogCheckpoint", JSON.stringify({ policy, checkpoint, expectedOrigin }));
    if (v.malformed !== undefined) this.malformed++;
    else if (v.ok) this.ok++;
    else this.refused++;
  }

  toString(): string {
    return `${this.ok} accepted, ${this.refused} refused, ${this.malformed} not checkpoints`;
  }
}

test("the builds judge a real checkpoint, altered every which way, alike", async () => {
  const split = CHECKPOINT.lastIndexOf("\n\n");
  const body = CHECKPOINT.slice(0, split + 1);
  const sigs = CHECKPOINT.slice(split + 2).split("\n").filter((l) => l !== "");
  const withSigs = (lines: string[], text = body) => text + "\n" + lines.map((l) => l + "\n").join("");
  const [origin, size, hash] = body.split("\n") as [string, string, string];
  const withBody = (text: string) => withSigs(sigs, text);

  const cases: string[] = [CHECKPOINT];
  for (let i = 0; i < sigs.length; i++) {
    cases.push(withSigs(sigs.filter((_, j) => j !== i)));                       // one signature removed
    cases.push(withSigs([...sigs, sigs[i]!]));                                   // repeated at the end
    cases.push(withSigs([...sigs.slice(0, i), sigs[i]!, ...sigs.slice(i)]));      // repeated in place
    cases.push(withSigs([sigs[i]!]));                                            // alone
    for (const at of [4, 5, 11, 12, 13, -1]) {                                   // key ID, timestamp, signature
      cases.push(editSignature(CHECKPOINT, i, (b) => { const k = at < 0 ? b.length + at : Math.min(at, b.length - 1); b[k]! ^= 1; }));
    }
    cases.push(editSignature(CHECKPOINT, i, (b) => { b[0]! ^= 1; }));             // a different key ID
    cases.push(editSignature(CHECKPOINT, i, (b) => b.subarray(0, b.length - 1))); // truncated
    cases.push(editSignature(CHECKPOINT, i, (b) => Buffer.concat([b, Buffer.from([0])])));
    cases.push(editSignature(CHECKPOINT, i, (b) => b.subarray(0, 4)));            // a key ID and nothing else
    cases.push(withSigs(sigs.map((l, j) => (j === i ? l.replace(/^— (\S+)/, "— $1x") : l))));
    cases.push(withSigs(sigs.map((l, j) => (j === i ? l.replace("— ", "- ") : l))));
    cases.push(withSigs(sigs.map((l, j) => (j === i ? l + " " : l))));
    cases.push(withSigs(sigs.map((l, j) => (j === i ? l.replace(/ (\S+)$/, "  $1") : l))));
  }
  cases.push(withSigs([...sigs].reverse()), withSigs([]), withSigs(sigs.slice(0, 2)), withSigs(sigs.slice(2)));
  // The body.
  for (const text of [
    `${origin}\n${Number(size) + 1}\n${hash}\n`, `${origin}\n0${size}\n${hash}\n`, `${origin}\n\n${hash}\n`, `${origin}\n-1\n${hash}\n`,
    `${origin}\n${size} \n${hash}\n`, `${origin}\n+${size}\n${hash}\n`, `${origin}\n${size}.0\n${hash}\n`, `${origin}\n99999999999999999999\n${hash}\n`,
    `${origin}x\n${size}\n${hash}\n`, `\n${size}\n${hash}\n`, `paic.google.com/log/1\n${size}\n${hash}\n`, ` ${origin}\n${size}\n${hash}\n`,
    `${origin}\n${size}\n${hash.replace("Uc=", "Ud=")}\n`, `${origin}\n${size}\n${hash.replace("=", "")}\n`, `${origin}\n${size}\n${hash}=\n`,
    `${origin}\n${size}\n${hash.slice(4)}\n`, `${origin}\n${size}\nAAAA${hash}\n`, `${origin}\n${size}\n${hash.replaceAll("+", "-").replaceAll("/", "_")}\n`,
    `${origin}\n${size}\n\n`, `${origin}\n${size}\n`, `${origin}\n`, "", "\n",
    `${origin}\n${size}\n${hash}\nextension\n`, `${origin}\n${size}\n${hash}\nextension one\nextension two\n`, `${origin}\n${size}\n${hash}\n\nextension\n`,
    `${origin}\n${size}\n${hash}\nextension\n\n`, `${origin}\n${size}\n${hash}\n \n`, `${origin}\n${size}\n${hash}\n\textension\n`,
    `${origin}\r\n${size}\r\n${hash}\r\n`, `${origin}\n${size}\n${hash}`, `${origin}\n${size}\n${hash}\n\0\n`,
  ]) cases.push(withBody(text));
  cases.push(CHECKPOINT.replaceAll("\n", "\r\n"), CHECKPOINT.slice(0, -1), CHECKPOINT + "\n", CHECKPOINT + " ", "\n" + CHECKPOINT,
    body + sigs.map((l) => l + "\n").join(""), body + "\n\n" + sigs.map((l) => l + "\n").join(""), body + "\n" + sigs.join("\n\n") + "\n",
    CHECKPOINT + "— example.com/witness " + Buffer.alloc(76, 7).toString("base64") + "\n",
    CHECKPOINT + "— a+b " + Buffer.alloc(76, 7).toString("base64") + "\n",
    CHECKPOINT + "— example.com/witness AAAA\n", CHECKPOINT + "— example.com/witness \n", CHECKPOINT + "— example.com/witness !!!!\n",
    CHECKPOINT + "trailing\n");

  const r = random(2);
  for (let i = 0; i < 700; i++) {
    let text = CHECKPOINT;
    for (let n = 1 + int(r, 2); n > 0; n--) text = r() < 0.5 ? mutateLines(r, text) : mutateText(r, text);
    cases.push(text);
  }
  // Mutations of the short first lines, which random positions rarely hit.
  for (let i = 0; i < 300; i++) cases.push(withBody(mutateText(r, body)));

  const verdicts = new Verdicts();
  for (const raw of cases) await verdicts.judge(POLICY, raw, "paic.google.com/log/0");
  await verdicts.judge(POLICY, CHECKPOINT, "paic.google.com/log/1");
  await verdicts.judge(POLICY, CHECKPOINT, "");
  await verdicts.judge("quorum none\n", CHECKPOINT, "");
  await verdicts.judge("frobnicate\n", CHECKPOINT, "");
  console.log(`checkpoints from the real log: ${cases.length + 4} judged alike (${verdicts})`);
  assert.ok(verdicts.ok > 20 && verdicts.refused > 100 && verdicts.malformed > 100);
});

test("the builds judge checkpoints signed for the purpose alike", async () => {
  const origin = "test.example/log";
  const logs = [await NoteKey.generate(origin, ED25519), await NoteKey.generate(origin, ML_DSA_44)];
  const otherLog = await NoteKey.generate("test.example/other", ED25519);
  const witnesses = [
    await NoteKey.generate("one.witness.example", ED25519_COSIGNATURE),
    await NoteKey.generate("two.witness.example", ML_DSA_44),
    await NoteKey.generate("three.witness.example", ED25519_COSIGNATURE),
    await NoteKey.generate("four.witness.example", ML_DSA_44),
  ];
  const stranger = await NoteKey.generate("stranger.example", ED25519_COSIGNATURE);
  const head = [...[...logs, otherLog].map((k) => `log ${k.vkey}`), ...witnesses.map((w, i) => `witness w${i + 1} ${w.vkey}`)].join("\n") + "\n";
  const policies = [
    head + "group g 2 w1 w2 w3\nquorum g\n",
    head + "group g all w1 w2 w3 w4\nquorum g\n",
    head + "group g any w1 w2 w3 w4\nquorum g\n",
    head + "group a any w1 w2\ngroup b any w3 w4\ngroup g all a b\nquorum g\n",
    head + "group a all w1 w2\ngroup g any a w4\nquorum g\n",
    head + "quorum w2\n",
    head + "quorum none\n",
  ];

  const now = Math.floor(Date.now() / 1000);
  const root = await sha256(utf8Encode("a root"));
  const empty = await sha256(new Uint8Array(0));
  /** A checkpoint with the given first lines, signed by the given keys at the given times. */
  async function signed(
    signers: NoteKey[], options: { origin?: string; size?: number; root?: Bytes; extensions?: string[]; time?: number } = {},
  ): Promise<string> {
    const cp = { origin: options.origin ?? origin, size: options.size ?? 42, root: options.root ?? root };
    const text = `${cp.origin}\n${cp.size}\n${b64Encode(cp.root)}\n${(options.extensions ?? []).map((l) => l + "\n").join("")}`;
    const lines = await Promise.all(signers.map((k) => k.sign(text, options.time ?? now)));
    return text + "\n" + lines.join("");
  }

  const cases: string[] = [];
  // Every combination of the log's keys and the witnesses.
  for (let l = 0; l < 4; l++) {
    for (let w = 0; w < 16; w++) {
      cases.push(await signed([...logs.filter((_, i) => l & (1 << i)), ...witnesses.filter((_, i) => w & (1 << i))]));
    }
  }
  const everyone = [...logs, ...witnesses];
  cases.push(
    await signed(everyone, { size: 0, root: empty }),
    await signed(everyone, { size: 2 ** 40 }),
    await signed(everyone, { size: Number.MAX_SAFE_INTEGER }),
    await signed(everyone, { extensions: ["an extension line"] }),
    await signed(everyone, { extensions: ["one", "two", "three"] }),
    await signed([logs[1]!, ...witnesses], { extensions: ["covered by no log signature over the text"] }),
    await signed([logs[1]!, witnesses[1]!, witnesses[3]!], { extensions: ["only ML-DSA throughout"] }),
    await signed(everyone, { time: 0 }),
    await signed(everyone, { time: 1 }),
    await signed(everyone, { time: now + 10 * 365 * 86400 }),
    // Signed by the right keys, but over a different log's name.
    await signed(everyone, { origin: "test.example/other" }),
    await signed([otherLog, ...witnesses], { origin: "test.example/other" }),
    await signed([otherLog, ...witnesses]),
    await signed(everyone, { origin: "test.example/unknown" }),
    await signed([...everyone, stranger]),
    await signed([stranger]),
    await signed([stranger, ...everyone]),
    await signed([...witnesses, ...logs]),
    await signed([...everyone, ...everyone]),
    await signed([logs[0]!, witnesses[0]!, witnesses[0]!, witnesses[1]!]),
  );
  // Valid signatures moved to a checkpoint they were not made for.
  const a = await signed(everyone);
  const b = await signed(everyone, { size: 43 });
  cases.push(b.slice(0, b.lastIndexOf("\n\n") + 2) + a.slice(a.lastIndexOf("\n\n") + 2));
  const r = random(3);
  for (let i = 0; i < 250; i++) cases.push(r() < 0.5 ? mutateLines(r, a) : mutateText(r, a));

  const verdicts = new Verdicts();
  for (const policy of policies) {
    for (const raw of cases) await verdicts.judge(policy, raw, origin);
  }
  console.log(`checkpoints signed for the purpose: ${cases.length} under ${policies.length} policies judged alike (${verdicts})`);
  assert.ok(verdicts.ok > 100 && verdicts.refused > 100 && verdicts.malformed > 100);
});

// ---------------------------------------------------------------------------
// The Merkle tree and proofs

test("the builds hash trees, and write and check proofs, alike", async () => {
  const r = random(5);
  const leaves = new Uint8Array(700 * 32);
  for (let i = 0; i < leaves.length; i++) leaves[i] = int(r, 256);
  const key = await NoteKey.generate("test.example/log", ED25519);
  const policy = `log ${key.vkey}\nquorum none\n`;
  const hexOf = (b: Bytes) => Buffer.from(b).toString("hex");

  const sizes = [0, ...Array.from({ length: 34 }, (_, i) => i + 1), 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 300, 511, 512, 513, 700];
  let proofs = 0;
  let last = "";
  let lastLeaf = "";
  for (const size of sizes) {
    const tree = await both<{ error?: string; root: string }>("tlogTree", leaves.subarray(0, size * 32), size);
    assert.equal(tree.error, undefined);
    if (size === 0) continue;
    const text = `test.example/log\n${size}\n${tree.root}\n`;
    const checkpoint = text + "\n" + await key.sign(text, 0);
    for (const index of new Set([0, size - 1, Math.floor(size / 2), int(r, size), int(r, size)])) {
      const { proof } = await both<{ proof: string }>("tlogProve", leaves.subarray(0, size * 32), size, index, checkpoint);
      const check = (leaf: number, text = proof) =>
        both<{ ok: boolean; error?: string }>("tlogCheckProof", JSON.stringify({ policy, proof: text, leafHash: hexOf(leaves.subarray(leaf * 32, leaf * 32 + 32)) }));
      // A proof proves its own leaf and no other.
      assert.deepEqual(await check(index), { ok: true, index, origin: "test.example/log", size });
      if (size > 1) assert.equal((await check((index + 1) % size)).ok, false);
      proofs++;
      last = proof;
      lastLeaf = hexOf(leaves.subarray(index * 32, index * 32 + 32));
    }
  }
  // Asking for what does not exist.
  await both("tlogTree", leaves.subarray(0, 64), 3);
  await both("tlogProve", leaves, 700, 700, "c\n");
  await both("tlogProve", leaves, 700, -1, "c\n");

  // Proofs that are not quite proofs.
  const leaf = lastLeaf;
  assert.equal((await both<{ ok: boolean }>("tlogCheckProof", JSON.stringify({ policy, proof: last, leafHash: leaf }))).ok, true);
  let refused = 0;
  for (let i = 0; i < 1500; i++) {
    const text = r() < 0.5 ? mutateLines(r, last) : mutateText(r, last);
    if (!(await both<{ ok: boolean }>("tlogCheckProof", JSON.stringify({ policy, proof: text, leafHash: leaf }))).ok) refused++;
  }
  for (const text of [last.replace(/index \d+/, "extra AAAA\n$&"), last.replace(/index /, "index 0"), last.replace(/index \d+/, "index -1"),
    last.replace(/index \d+/, "index 18446744073709551616"), last.replace("@v1", "@v2"), last.replace(/\n\n/, "\n"), ""]) {
    await both("tlogCheckProof", JSON.stringify({ policy, proof: text, leafHash: leaf }));
  }
  console.log(`trees and proofs: ${sizes.length} trees and ${proofs} proofs alike; ${refused} of 1500 altered proofs refused alike`);
  assert.ok(refused > 1000 && refused < 1500);
});

// ---------------------------------------------------------------------------
// Tiles and bundles

test("the builds lay out logs, split bundles and hash leaves alike", async () => {
  const r = random(7);
  let tiles = 0;
  for (const [from, size] of [[0, 0], [0, 1], [0, 255], [0, 256], [0, 257], [0, 70000], [600, 700], [512, 1030], [700, 700], [700, 600],
    [1234067 * 256, 1234067 * 256 + 146], [2 ** 40, 2 ** 40 + 1000]] as const) {
    tiles += (await both<{ tiles: unknown[] }>("tlogLayout", JSON.stringify({ from, size }))).tiles.length;
  }
  const bundle = new Uint8Array(testdata("entries-first7.bin"));
  const entries = await both<Uint8Array[]>("tlogBundle", bundle);
  assert.equal(entries.length, 7);
  for (const e of entries) assert.equal((await both<Uint8Array>("tlogLeafHash", e)).length, 32);
  await both("tlogLeafHash", new Uint8Array(0));
  let refused = 0;
  for (let i = 0; i < 400; i++) {
    const altered = bundle.slice(0, r() < 0.5 ? bundle.length : int(r, bundle.length));
    for (let n = int(r, 3); n > 0; n--) altered[int(r, Math.min(altered.length, 4000))]! ^= 1 << int(r, 8);
    if (!Array.isArray(await both("tlogBundle", altered))) refused++;
  }
  console.log(`tiles and bundles: ${tiles} tiles laid out alike; ${refused} of 400 altered bundles refused alike`);
  assert.ok(refused > 50 && refused < 400);
});
