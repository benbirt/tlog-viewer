// https://c2sp.org/tlog-proof: a self-contained proof that an entry is in a
// log, made of the entry's index, its inclusion proof, and the signed and
// witnessed checkpoint the proof leads to. Anyone holding the entry and a
// trust policy can check it offline.

import { b64Decode, b64Encode, type Bytes } from "./bytes.js";

const HEADER = "c2sp.org/tlog-proof@v1";

export interface TlogProof {
  index: number;
  hashes: Bytes[];
  /** The signed checkpoint, exactly as the log served it. */
  checkpoint: string;
}

export function formatTlogProof(p: TlogProof): string {
  return [HEADER, `index ${p.index}`, ...p.hashes.map((h) => b64Encode(h)), "", p.checkpoint].join("\n");
}

/** Parses a tlog-proof without extra data, which is all this viewer writes. */
export function parseTlogProof(text: string): TlogProof {
  const end = text.indexOf("\n\n");
  if (end < 0) throw new Error("malformed tlog-proof");
  const [header, indexLine, ...hashLines] = text.slice(0, end).split("\n");
  const index = /^index (0|[1-9][0-9]*)$/.exec(indexLine ?? "");
  if (header !== HEADER || !index || !Number.isSafeInteger(Number(index[1]))) throw new Error("malformed tlog-proof");
  // What follows is a signed note, which ends with a newline.
  if (!text.endsWith("\n")) throw new Error("malformed tlog-proof");
  const hashes = hashLines.map((l) => b64Decode(l));
  if (hashes.some((h) => h.length !== 32)) throw new Error("malformed tlog-proof");
  return { index: Number(index[1]), hashes, checkpoint: text.slice(end + 2) };
}
