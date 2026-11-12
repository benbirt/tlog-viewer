// Differential tests: the TypeScript verifier against the Go implementations
// of the same formats, on valid input, on hand-made awkward input and on
// thousands of mutations of both.
//
// The rule being tested is that the page never accepts what the Go code
// rejects. Where the page is stricter than the Go code on purpose, the reason
// is named in STRICTER below and counted; any other disagreement fails.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { before, test } from "node:test";
import { b64Encode, type Bytes, concat, hex, sha256, utf8Encode } from "../../web/js/bytes.js";
import { inclusionProof, rootFromLeafHashes } from "../../web/js/merkle.js";
import { resultFromInspection } from "../../web/js/goengine.js";
import { type CheckpointResult, newVerifier, verifyCheckpoint } from "../../web/js/note.js";
import { ALG_ED25519, ALG_ED25519_COSIG, ALG_MLDSA44, parsePolicy } from "../../web/js/policy.js";
import { POLICY_TEXT } from "../../web/js/policy_data.js";
import { formatTlogProof, parseTlogProof } from "../../web/js/proof.js";
import { NoteKey } from "../e2e/testlog.js";
import { loadOracle, type Oracle, type OracleCheckpoint, type OraclePolicy } from "./oracle.js";

const testdata = (f: string) => readFileSync(new URL("../testdata/" + f, import.meta.url));
const POLICY = testdata("prod-verifier-668ba3c.policy").toString();
const CHECKPOINT = testdata("checkpoint-5522.txt").toString();

let oracle: Oracle;
before(async () => { oracle = await loadOracle(); });

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
// Comparing

/** Disagreements seen, for a readable failure; and deliberate ones, by reason. */
class Tally {
  agreed = 0;
  readonly stricter = new Map<string, number>();
  readonly failures: string[] = [];

  fail(what: string, input: string, detail: string): void {
    if (this.failures.length < 12) this.failures.push(`${what}\n  ${detail}\n  input: ${JSON.stringify(input.length > 400 ? input.slice(0, 400) + "…" : input)}`);
    else if (this.failures.length === 12) this.failures.push("… and more");
  }

  finish(name: string): void {
    const explained = [...this.stricter].map(([reason, n]) => `${n} stricter (${reason})`).join(", ");
    console.log(`${name} [${oracle.variant}]: ${this.agreed} agree${explained ? ", " + explained : ""}`);
    assert.equal(this.failures.length, 0, `${name}: the TypeScript and Go implementations disagree:\n\n${this.failures.join("\n\n")}`);
  }
}

/**
 * Where the page rejects what the Go code accepts, on purpose. Each entry
 * matches the page's own explanation of why it rejected.
 */
const STRICTER: [reason: string, pattern: RegExp][] = [
  // tlog-checkpoint: "There MUST NOT be multiple signature lines with both
  // the same key name and the same key id." sumdb/note drops repeats instead.
  ["repeated signature line", /more than one signature line/],
  // The formats require canonical base64. Go's decoder accepts stray bits in
  // the final character.
  ["non-canonical base64", /non-canonical base64/],
  // signed-note: a key name has no "+"; sumdb/note only checks names it knows.
  ["malformed signature line", /bad signature line/],
  // tlog-checkpoint: extension lines are non-empty. sumdb/note takes the
  // last blank line as the separator, so an earlier one is an empty line.
  ["empty or control-character extension line", /bad extension line/],
];

const stricterReason = (explanation: string, reasons = STRICTER): string | null =>
  reasons.find(([, pattern]) => pattern.test(explanation))?.[0] ?? null;

/** The same, for policies. */
const POLICY_STRICTER: [reason: string, pattern: RegExp][] = [
  // signed-note: a key ID is the first four bytes of SHA-256(name, newline,
  // type, key), in eight lower-case hex digits. For cosignature keys the Go
  // code checks only that eight characters are there, and uses the ID it
  // computes itself.
  ["key ID is not the one the name and key imply", /key id mismatch|malformed key id/],
  // Go accepts anything url.Parse does, relative references included.
  ["URL is not absolute http(s)", /not an absolute http\(s\) URL/],
];

// ---------------------------------------------------------------------------
// Policies

type PolicyView = Omit<OraclePolicy, "error"> | { error: string };

/** The page's reading of a policy, including the per-key checks it makes before using one. */
async function tsPolicy(text: string): Promise<PolicyView> {
  try {
    const p = parsePolicy(text);
    for (const { vkey } of [...p.logs, ...p.witnesses]) await newVerifier(vkey);
    return {
      logs: p.logs.map((l) => l.vkey.text),
      witnesses: p.witnesses.map((w) => ({ name: w.name, vkey: w.vkey.text })),
      groups: p.groups.map((g) => ({ name: g.name, threshold: g.threshold, members: g.members })),
      quorum: p.quorum,
    };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

async function comparePolicy(tally: Tally, text: string): Promise<void> {
  const go = oracle.parsePolicy(text);
  const ts = await tsPolicy(text);
  const goAccepts = go.error === undefined;
  const tsAccepts = !("error" in ts);
  if (tsAccepts && !goAccepts) return tally.fail("the page accepts a policy Go rejects", text, `go: ${go.error}`);
  if ("error" in ts && goAccepts) {
    const reason = stricterReason(ts.error, POLICY_STRICTER);
    if (reason === null) return tally.fail("the page rejects a policy Go accepts", text, `page: ${ts.error}`);
    tally.stricter.set(reason, (tally.stricter.get(reason) ?? 0) + 1);
    return;
  }
  if (goAccepts && tsAccepts) {
    const { error: _error, ...goView } = go;
    try {
      assert.deepEqual(ts, goView);
    } catch {
      return tally.fail("the page and Go read a policy differently", text, `go: ${JSON.stringify(goView)}\n  page: ${JSON.stringify(ts)}`);
    }
  }
  tally.agreed++;
}

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

test("policies are read as the Go implementation reads them", async () => {
  const tally = new Tally();
  for (const text of [POLICY, POLICY_TEXT, ...handMadePolicies()]) await comparePolicy(tally, text);
  const r = random(1);
  // A shorter policy keeps mutations from landing mostly in key material.
  const small = POLICY.split("\n").filter((l) => !l.startsWith("#") && l !== "").filter((l, i) => i < 3 || !l.startsWith("log ")).join("\n") + "\n";
  for (let i = 0; i < 1500; i++) {
    let text = pick(r, [POLICY, small, small]);
    for (let n = 1 + int(r, 3); n > 0; n--) text = r() < 0.6 ? mutateLines(r, text) : mutateText(r, text);
    await comparePolicy(tally, text);
  }
  tally.finish("policies");
});

// ---------------------------------------------------------------------------
// Checkpoints

interface CheckpointView {
  ok: boolean;
  origin?: string;
  size?: number;
  hash?: string;
  logSigned: boolean;
  quorum: boolean;
  witnesses: string[];
  /** Why the page did not accept, in its own words. */
  explanation: string;
  /** The page could not read it as a signed checkpoint at all. */
  malformed: boolean;
}

async function tsCheckpoint(policyText: string, raw: string): Promise<CheckpointView> {
  try {
    const r = await verifyCheckpoint(parsePolicy(policyText), raw);
    return {
      ok: r.ok,
      origin: r.checkpoint.origin,
      size: r.checkpoint.size,
      hash: b64Encode(r.checkpoint.hash),
      logSigned: r.logSigned,
      quorum: r.quorum.satisfied,
      witnesses: [...new Set(r.signatures.filter((s) => s.status === "valid" && s.witness !== null).map((s) => s.witness!))].sort(),
      explanation: r.problems.join("; "),
      malformed: false,
    };
  } catch (e) {
    return { ok: false, logSigned: false, quorum: false, witnesses: [], explanation: e instanceof Error ? e.message : String(e), malformed: true };
  }
}

async function compareCheckpoint(tally: Tally, policyText: string, raw: string): Promise<void> {
  const go: OracleCheckpoint = oracle.verifyCheckpoint(policyText, raw);
  assert.equal(go.policyError, undefined, "the test's policy must be valid");
  const ts = await tsCheckpoint(policyText, raw);

  if (ts.ok && !go.ok) return tally.fail("the page accepts a checkpoint Go rejects", raw, `go: ${go.error}`);
  if (!ts.ok && go.ok) {
    const reason = stricterReason(ts.explanation);
    if (reason === null) return tally.fail("the page rejects a checkpoint Go accepts", raw, `page: ${ts.explanation}`);
    tally.stricter.set(reason, (tally.stricter.get(reason) ?? 0) + 1);
    return;
  }
  if (ts.ok) {
    if (ts.origin !== go.origin || ts.size !== go.size || ts.hash !== go.hash) {
      return tally.fail("the page and Go read a checkpoint differently", raw,
        `go: ${go.origin} ${go.size} ${go.hash}; page: ${ts.origin} ${ts.size} ${ts.hash}`);
    }
  }
  // Short of the verdict, the two halves and the cosigners must match too,
  // wherever the page could read the checkpoint at all. (Go reports on the
  // signatures of some texts that are not checkpoints.)
  if (!ts.malformed && (ts.logSigned !== go.logSigned || ts.quorum !== go.quorum || ts.witnesses.join() !== go.witnesses.join())) {
    return tally.fail("the page and Go disagree about a checkpoint's signatures", raw,
      `go: log ${go.logSigned}, quorum ${go.quorum}, witnesses [${go.witnesses}]\n  page: log ${ts.logSigned}, quorum ${ts.quorum}, witnesses [${ts.witnesses}] (${ts.explanation})`);
  }
  tally.agreed++;
}

test("a real checkpoint, altered every which way, is judged as the Go implementation judges it", async () => {
  const tally = new Tally();
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

  for (const raw of cases) await compareCheckpoint(tally, POLICY, raw);
  tally.finish(`checkpoints from the real log (${cases.length})`);
});

test("checkpoints signed for the purpose are judged as the Go implementation judges them", async () => {
  const tally = new Tally();
  const origin = "test.example/log";
  const logs = [await NoteKey.generate(origin, ALG_ED25519), await NoteKey.generate(origin, ALG_MLDSA44)];
  const otherLog = await NoteKey.generate("test.example/other", ALG_ED25519);
  const witnesses = [
    await NoteKey.generate("one.witness.example", ALG_ED25519_COSIG),
    await NoteKey.generate("two.witness.example", ALG_MLDSA44),
    await NoteKey.generate("three.witness.example", ALG_ED25519_COSIG),
    await NoteKey.generate("four.witness.example", ALG_MLDSA44),
  ];
  const stranger = await NoteKey.generate("stranger.example", ALG_ED25519_COSIG);
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
    signers: NoteKey[], options: { origin?: string; size?: number; root?: Bytes; extensions?: string[]; time?: number; signedOrigin?: string } = {},
  ): Promise<string> {
    const cp = { origin: options.origin ?? origin, size: options.size ?? 42, root: options.root ?? root };
    const text = `${cp.origin}\n${cp.size}\n${b64Encode(cp.root)}\n${(options.extensions ?? []).map((l) => l + "\n").join("")}`;
    const lines = await Promise.all(signers.map((k) => k.sign({ ...cp, origin: options.signedOrigin ?? cp.origin, text }, options.time ?? now)));
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
    await signed(everyone, { time: 2 ** 53 + 2 }),
    // Signed by the right keys, but over a different log's name.
    await signed(everyone, { origin: "test.example/other" }),
    await signed([otherLog, ...witnesses], { origin: "test.example/other" }),
    await signed([otherLog, ...witnesses]),
    await signed(everyone, { origin: "test.example/unknown" }),
    await signed(everyone, { signedOrigin: "test.example/other" }),
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

  for (const policy of policies) {
    for (const raw of cases) await compareCheckpoint(tally, policy, raw);
  }
  tally.finish(`checkpoints signed for the purpose (${cases.length} under ${policies.length} policies)`);
});

// ---------------------------------------------------------------------------
// Proofs

test("tlog-proofs are written and read as the Go implementation writes and reads them", async () => {
  const tally = new Tally();
  const leaves = concat(...await Promise.all(Array.from({ length: 40 }, (_, i) => sha256(utf8Encode(`leaf ${i}`)))));
  const hashes = await inclusionProof(leaves, 17, 40);
  const proof = { index: 17, hashes, checkpoint: CHECKPOINT };
  const text = formatTlogProof(proof);

  // Written the same...
  assert.equal(oracle.formatProof({ index: 17, hashes: hashes.map((h) => b64Encode(h)), checkpoint: CHECKPOINT }), text);
  for (const p of [{ index: 0, hashes: [] as Bytes[], checkpoint: CHECKPOINT }, { index: 2 ** 40, hashes: hashes.slice(0, 1), checkpoint: "c\n" }]) {
    assert.equal(oracle.formatProof({ ...p, hashes: p.hashes.map((h) => b64Encode(h)) }), formatTlogProof(p));
  }

  // ...and read the same, or, where the page is stricter, refused.
  const compare = (input: string) => {
    const go = oracle.parseProof(input);
    let ts: { index: number; hashes: string[]; checkpoint: string } | { error: string };
    try {
      const p = parseTlogProof(input);
      ts = { index: p.index, hashes: p.hashes.map((h) => b64Encode(h)), checkpoint: p.checkpoint };
    } catch (e) {
      ts = { error: e instanceof Error ? e.message : String(e) };
    }
    if (!("error" in ts) && go.error !== undefined) return tally.fail("the page reads a proof Go rejects", input, `go: ${go.error}`);
    if ("error" in ts) {
      // The page writes one form of proof and reads only that. Go's reader
      // also takes "extra" data and is forgiving about the rest.
      tally.stricter.set("not the form of proof the page writes", (tally.stricter.get("not the form of proof the page writes") ?? 0) + (go.error === undefined ? 1 : 0));
      if (go.error !== undefined) tally.agreed++;
      return;
    }
    if (ts.index !== go.index || ts.hashes.join() !== go.hashes.join() || ts.checkpoint !== go.checkpoint) {
      return tally.fail("the page and Go read a proof differently", input, `go: ${JSON.stringify(go).slice(0, 300)}\n  page: ${JSON.stringify(ts).slice(0, 300)}`);
    }
    tally.agreed++;
  };
  compare(text);
  compare(text.replace("index 17", "extra AAAA\nindex 17"));
  compare(text.replace("index 17", "index 017"));
  compare(text.replace("index 17", "index -1"));
  compare(text.replace("index 17", "index 18446744073709551616"));
  compare(text.replace("@v1", "@v2"));
  compare(text.replace(/\n\n/, "\n"));
  const short = formatTlogProof({ index: 17, hashes, checkpoint: "origin\n1\nAAAA\n\n— k AAAAAAAA\n" });
  const r = random(4);
  for (let i = 0; i < 1500; i++) compare(r() < 0.5 ? mutateLines(r, short) : mutateText(r, short));
  tally.finish("proofs");
});

// ---------------------------------------------------------------------------
// The Merkle tree

test("tree heads and inclusion proofs equal the Go implementation's", async () => {
  const r = random(5);
  const leaves = new Uint8Array(700 * 32);
  for (let i = 0; i < leaves.length; i++) leaves[i] = int(r, 256);
  const sizes = [...Array.from({ length: 34 }, (_, i) => i + 1), 63, 64, 65, 100, 127, 128, 129, 255, 256, 257, 300, 511, 512, 513, 700];
  let compared = 0;
  for (const size of sizes) {
    const indices = new Set([0, size - 1, Math.floor(size / 2), int(r, size), int(r, size), int(r, size)]);
    for (const index of indices) {
      const go = oracle.tree(leaves, size, index);
      assert.equal(go.error, undefined);
      assert.equal(hex(await rootFromLeafHashes(leaves, size)), go.root, `root of ${size}`);
      assert.deepEqual((await inclusionProof(leaves, index, size)).map((h) => hex(h)), go.proof, `proof of ${index} in ${size}`);
      compared++;
    }
  }
  console.log(`tree heads and inclusion proofs [${oracle.variant}]: ${compared} agree`);
});

// ---------------------------------------------------------------------------
// The page's Go engine

test("the page's Go engine and its TypeScript verifier give the page the same result", async () => {
  // engine=go has the page take its checkpoint result from the Go code
  // (goengine.ts). Whatever the page would show must not depend on the engine.
  const policy = parsePolicy(POLICY);
  const options = { expectedOrigin: "paic.google.com/log/0" };
  const split = CHECKPOINT.lastIndexOf("\n\n");
  const body = CHECKPOINT.slice(0, split + 1);
  const sigs = CHECKPOINT.slice(split + 2).split("\n").filter((l) => l !== "");
  const withSigs = (lines: string[], text = body) => text + "\n" + lines.map((l) => l + "\n").join("");

  const cases: string[] = [CHECKPOINT];
  for (let i = 0; i < sigs.length; i++) {
    cases.push(withSigs(sigs.filter((_, j) => j !== i)));
    cases.push(withSigs([sigs[i]!]));
    cases.push(withSigs([...sigs, sigs[i]!]));
    for (const at of [0, 5, 12, -1]) {
      cases.push(editSignature(CHECKPOINT, i, (b) => { b[at < 0 ? b.length + at : at]! ^= 1; }));
    }
  }
  cases.push(withSigs([]), withSigs(sigs.slice(0, 2)), withSigs(sigs.slice(2)), withSigs([...sigs].reverse()),
    withSigs(sigs, body.replace("5522", "5523")), withSigs(sigs, body.replace("log/0", "log/1")), withSigs(sigs, body + "extension\n"),
    CHECKPOINT + "— example.com/witness " + Buffer.alloc(76, 7).toString("base64") + "\n");
  const r = random(6);
  for (let i = 0; i < 150; i++) cases.push(mutateLines(r, CHECKPOINT));

  /** What the page displays of a result, in comparable form. */
  const shown = (res: CheckpointResult) => ({
    ok: res.ok,
    origin: res.checkpoint.origin,
    size: res.checkpoint.size,
    hash: b64Encode(res.checkpoint.hash),
    extensions: res.checkpoint.extensions,
    text: res.text,
    signatures: res.signatures.map((s) => ({ ...s, timestamp: s.timestamp?.toString() ?? null })),
    logSigned: res.logSigned,
    quorum: res.quorum,
    quorumPossible: res.quorumPossible,
    witnessedAt: res.witnessedAt?.toString() ?? null,
    extensionsAuthenticated: res.extensionsAuthenticated,
    problems: res.problems,
    warnings: res.warnings,
  });

  let same = 0;
  let malformed = 0;
  let repeats = 0;
  let refusedByGo = 0;
  for (const raw of cases) {
    let ts: CheckpointResult | Error;
    let go: CheckpointResult | Error;
    try { ts = await verifyCheckpoint(policy, raw, options); } catch (e) { ts = e as Error; }
    try { go = resultFromInspection(policy, oracle.inspectCheckpoint(POLICY, raw), options); } catch (e) { go = e as Error; }
    if (ts instanceof Error) {
      // The TypeScript refuses some texts outright that Go reads; then Go must at least not accept them,
      // unless it is one of the forms the page is deliberately stricter about.
      if (!(go instanceof Error) && go.ok) assert.notEqual(stricterReason(ts.message), null, `Go engine accepts what the page refuses (${ts.message}): ${JSON.stringify(raw.slice(0, 200))}`);
      malformed++;
      continue;
    }
    if (go instanceof Error) {
      // Go may refuse outright what the TypeScript reads and then rejects; never what it accepts.
      assert.ok(!ts.ok, `Go engine refuses what the page accepts: ${go.message}\n${JSON.stringify(raw.slice(0, 300))}`);
      refusedByGo++;
      continue;
    }
    // Go's note reader drops a signature line identical to an earlier one, so
    // its engine never sees the repeat that the TypeScript rejects.
    if (ts.problems.some((p) => /more than one signature line/.test(p)) && go.signatures.length < ts.signatures.length) {
      repeats++;
      continue;
    }
    assert.deepEqual(shown(go), shown(ts), JSON.stringify(raw.slice(0, 300)));
    same++;
  }
  console.log(`the page's two engines [${oracle.variant}]: ${same} identical results, ${malformed} refused by the TypeScript, ${repeats} with a repeated line only it sees, ${refusedByGo} refused by Go alone`);
  assert.ok(same > 100);
});
