// Parser and quorum evaluation for https://c2sp.org/tlog-policy files.

import { b64Decode, type Bytes, hex } from "./bytes.js";

export const ALG_ED25519 = 0x01;
export const ALG_ED25519_COSIG = 0x04;
export const ALG_MLDSA44 = 0x06;

export const ALG_NAMES: Record<number, string> = {
  [ALG_ED25519]: "Ed25519",
  [ALG_ED25519_COSIG]: "Ed25519 cosignature",
  [ALG_MLDSA44]: "ML-DSA-44",
};

export interface VKey {
  text: string;
  name: string;
  keyId: number;
  /** The signature type byte that prefixes the key. */
  alg: number;
  key: Bytes;
}

export interface Log {
  vkey: VKey;
  url: string | null;
}

export interface Witness {
  /** The witness's name within the policy, which is not its key name. */
  name: string;
  vkey: VKey;
  url: string | null;
}

export interface Group {
  name: string;
  threshold: number;
  members: string[];
}

export interface Policy {
  logs: Log[];
  witnesses: Witness[];
  groups: Group[];
  /** The witness or group that must have cosigned, or "none". */
  quorum: string;
}

/** A quorum rule evaluated against a set of cosigners. */
export type QuorumNode =
  | { kind: "none"; name: "none"; satisfied: true }
  | { kind: "witness"; name: string; satisfied: boolean }
  | { kind: "group"; name: string; satisfied: boolean; threshold: number; count: number; children: QuorumNode[] };

/** Parses "<name>+<8 hex key id>+<base64(type byte || key)>". */
export function parseVKey(text: string): VKey {
  const first = text.indexOf("+");
  const second = text.indexOf("+", first + 1);
  if (first <= 0 || second < 0) throw new Error(`malformed vkey: ${text.slice(0, 60)}`);
  const name = text.slice(0, first);
  if (/[\s\x00-\x1f\x7f]/.test(name)) throw new Error(`malformed key name in vkey: ${text.slice(0, 60)}`);
  const idHex = text.slice(first + 1, second);
  if (!/^[0-9a-f]{8}$/.test(idHex)) throw new Error(`malformed key id in vkey for ${name}`);
  const raw = b64Decode(text.slice(second + 1));
  if (raw.length < 2) throw new Error(`empty key in vkey for ${name}`);
  return { text, name, keyId: parseInt(idHex, 16), alg: raw[0]!, key: raw.subarray(1) };
}

/** Accepts the optional URL of a log or witness line if it is an absolute http(s) URL. */
function checkUrl(url: string | undefined, fail: (msg: string) => never): string | null {
  if (url === undefined) return null;
  if (!/^https?:\/\//.test(url) || /%(?![0-9A-Fa-f]{2})/.test(url) || !URL.canParse(url)) fail(`not an absolute http(s) URL: ${url}`);
  return url;
}

export function parsePolicy(text: string): Policy {
  // The only control characters a policy may contain are tab and newline.
  if (/[\x00-\x08\x0b-\x1f\x7f]/.test(text)) throw new Error("policy contains a control character");
  const logs: Log[] = [];
  const witnesses: Witness[] = [];
  const groups: Group[] = [];
  let quorum: string | null = null;
  const names = new Set<string>();
  // Two vkeys wrapping the same public key are duplicates, whatever their names.
  const logKeys = new Set<string>();
  const witnessKeys = new Set<string>();
  // Names already listed as a member of some group.
  const grouped = new Set<string>();

  text.split("\n").forEach((line, i) => {
    const fields = line.split(/[ \t]+/).filter((f) => f !== "");
    if (fields[0] === undefined || fields[0].startsWith("#")) return;
    const fail = (msg: string): never => {
      throw new Error(`line ${i + 1}: ${msg}`);
    };
    const define = (name: string) => {
      if (name === "none") fail('"none" is reserved');
      if (names.has(name)) fail(`duplicate name ${name}`);
      names.add(name);
    };
    const [keyword, ...args] = fields;
    switch (keyword) {
      case "log": {
        const [vkey, url] = args;
        if (vkey === undefined || args.length > 2) return fail("malformed log line");
        const parsed = parseVKey(vkey);
        if (logKeys.has(hex(parsed.key))) fail(`duplicate log public key ${parsed.name}`);
        logKeys.add(hex(parsed.key));
        logs.push({ vkey: parsed, url: checkUrl(url, fail) });
        break;
      }
      case "witness": {
        const [name, vkeyText, url] = args;
        if (name === undefined || vkeyText === undefined || args.length > 3) return fail("malformed witness line");
        define(name);
        const vkey = parseVKey(vkeyText);
        if (vkey.alg !== ALG_ED25519_COSIG && vkey.alg !== ALG_MLDSA44) {
          fail(`witness ${name} does not use a cosignature key type`);
        }
        if (witnessKeys.has(hex(vkey.key))) fail(`duplicate witness public key ${name}`);
        witnessKeys.add(hex(vkey.key));
        witnesses.push({ name, vkey, url: checkUrl(url, fail) });
        break;
      }
      case "group": {
        const [name, thresholdText, ...members] = args;
        if (name === undefined || thresholdText === undefined || members.length === 0) return fail("malformed group line");
        if (name === "none") fail('"none" is reserved');
        if (names.has(name)) fail(`duplicate name ${name}`);
        let threshold: number;
        if (thresholdText === "any") threshold = 1;
        else if (thresholdText === "all") threshold = members.length;
        else if (/^[0-9]+$/.test(thresholdText) && Number(thresholdText) < 2 ** 31) threshold = Number(thresholdText);
        else return fail(`bad threshold ${thresholdText}`);
        if (threshold < 1 || threshold > members.length) fail(`threshold ${threshold} is outside 1 to ${members.length}`);
        for (const m of members) {
          if (!names.has(m)) fail(`group ${name} references undefined ${m}`);
          // Across the whole policy, not just this group: the groups form a tree.
          if (grouped.has(m)) fail(`${m} is a member of more than one group, or of one group twice`);
          grouped.add(m);
        }
        define(name);
        groups.push({ name, threshold, members });
        break;
      }
      case "quorum": {
        const [name] = args;
        if (name === undefined || args.length !== 1) return fail("malformed quorum line");
        if (quorum !== null) fail("more than one quorum line");
        if (name !== "none" && !names.has(name)) fail(`quorum references undefined ${name}`);
        quorum = name;
        break;
      }
      default:
        fail(`unknown keyword ${keyword}`);
    }
  });
  if (quorum === null) throw new Error("policy has no quorum line");
  return { logs, witnesses, groups, quorum };
}

/** The distinct log origins a policy trusts, in order of first appearance. */
export function logOrigins(policy: Policy): string[] {
  return [...new Set(policy.logs.map((l) => l.vkey.name))];
}

/**
 * Evaluates the quorum rule given the policy-local names of the witnesses
 * whose cosignatures verified.
 */
export function evaluateQuorum(policy: Policy, validWitnesses: ReadonlySet<string>): QuorumNode {
  if (policy.quorum === "none") return { kind: "none", name: "none", satisfied: true };
  const groups = new Map(policy.groups.map((g) => [g.name, g]));
  const evalName = (name: string): QuorumNode => {
    const g = groups.get(name);
    if (!g) return { kind: "witness", name, satisfied: validWitnesses.has(name) };
    const children = g.members.map(evalName);
    const count = children.filter((c) => c.satisfied).length;
    return { kind: "group", name, threshold: g.threshold, count, satisfied: count >= g.threshold, children };
  };
  return evalName(policy.quorum);
}
