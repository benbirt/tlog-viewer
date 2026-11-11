// Client for https://c2sp.org/tlog-tiles logs.

import type { Bytes } from "./bytes.js";

export const TILE_WIDTH = 256;

export interface TileRef {
  index: number;
  /** Number of hashes or entries in the tile; less than TILE_WIDTH if partial. */
  width: number;
}

/** Encodes a tile index as zero-padded 3-digit path elements (x001/x234/067). */
export function encodeIndex(n: number): string {
  const groups: string[] = [];
  do {
    groups.unshift(String(n % 1000).padStart(3, "0"));
    n = Math.floor(n / 1000);
  } while (n > 0);
  return groups.map((g, i) => (i < groups.length - 1 ? "x" + g : g)).join("/");
}

export function tilePath(level: number | "entries", index: number, width: number = TILE_WIDTH): string {
  const partial = width < TILE_WIDTH ? `.p/${width}` : "";
  return `tile/${level}/${encodeIndex(index)}${partial}`;
}

/** The level-0 tiles (and entry bundles) covering a tree of `size` leaves. */
export function tilesForSize(size: number): TileRef[] {
  const tiles: TileRef[] = [];
  for (let index = 0; index * TILE_WIDTH < size; index++) {
    tiles.push({ index, width: Math.min(TILE_WIDTH, size - index * TILE_WIDTH) });
  }
  return tiles;
}

/** Splits an entry bundle into its big-endian uint16 length-prefixed entries. */
export function parseBundle(bytes: Bytes): Bytes[] {
  const entries: Bytes[] = [];
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let off = 0;
  while (off < bytes.length) {
    if (off + 2 > bytes.length) throw new Error("truncated entry bundle");
    const len = dv.getUint16(off);
    off += 2;
    if (off + len > bytes.length) throw new Error("truncated entry bundle");
    entries.push(bytes.subarray(off, off + len));
    off += len;
  }
  return entries;
}

export class HttpError extends Error {
  constructor(readonly url: string, readonly status: number) {
    super(`${url}: HTTP ${status}`);
  }
}

export type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

export class LogClient {
  readonly #fetch: Fetch;

  /** @param base URL prefix ending in "/". */
  constructor(readonly base: string, fetchFn: Fetch = (url, init) => fetch(url, init)) {
    this.#fetch = fetchFn;
  }

  url(path: string): string {
    return this.base + path;
  }

  async #get(path: string, init?: RequestInit): Promise<Response> {
    const url = this.url(path);
    const res = await this.#fetch(url, init);
    if (!res.ok) throw new HttpError(url, res.status);
    return res;
  }

  async #bytes(path: string): Promise<Bytes> {
    return new Uint8Array(await (await this.#get(path)).arrayBuffer());
  }

  async checkpoint(): Promise<string> {
    return (await this.#get("checkpoint", { cache: "no-store" })).text();
  }

  async hashTile({ index, width }: TileRef): Promise<Bytes> {
    const bytes = await this.#bytes(tilePath(0, index, width));
    if (bytes.length !== width * 32) throw new Error(`hash tile ${index} has the wrong size`);
    return bytes;
  }

  async entryBundle({ index, width }: TileRef): Promise<Bytes[]> {
    const entries = parseBundle(await this.#bytes(tilePath("entries", index, width)));
    if (entries.length !== width) throw new Error(`entry bundle ${index} has ${entries.length} entries, want ${width}`);
    return entries;
  }
}
