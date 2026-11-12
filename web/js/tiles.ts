// Fetching from https://c2sp.org/tlog-tiles logs. Where a log keeps things,
// and what is in them, is the verifier's to say (verifier.ts): this only
// makes the requests.

import type { Bytes } from "./bytes.js";

export class HttpError extends Error {
  constructor(readonly url: string, readonly status: number) {
    super(`${url}: HTTP ${status}`);
  }
}

export type Fetch = (url: string, init?: RequestInit) => Promise<Response>;

/** A file fetched from a log, other than its checkpoint. */
export type LogFile =
  | { kind: "hashes"; level: number; index: number }
  | { kind: "entries"; index: number };

/**
 * Changes to make to what a log serves before it is used, for simulating
 * failures (faults.ts). "error" fails the request.
 */
export interface Tamper {
  checkpoint?: (raw: string) => string;
  tile?: (file: LogFile, bytes: Bytes) => Bytes | "error";
}

export class LogClient {
  readonly #fetch: Fetch;

  /**
   * @param base URL prefix ending in "/".
   * @param signal Aborts every request the client has in flight or makes later.
   * @param tamper Alters what was fetched, to simulate a failure.
   */
  constructor(
    readonly base: string, fetchFn: Fetch = (url, init) => fetch(url, init), readonly signal?: AbortSignal,
    private readonly tamper?: Tamper,
  ) {
    this.#fetch = fetchFn;
  }

  url(path: string): string {
    return this.base + path;
  }

  async #get(path: string, init?: RequestInit): Promise<Response> {
    const url = this.url(path);
    const res = await this.#fetch(url, { ...init, signal: this.signal ?? null });
    if (!res.ok) throw new HttpError(url, res.status);
    return res;
  }

  /** Fetches the log's checkpoint, never from a cache. */
  async checkpoint(path: string): Promise<string> {
    const raw = await (await this.#get(path, { cache: "no-store" })).text();
    return this.tamper?.checkpoint ? this.tamper.checkpoint(raw) : raw;
  }

  async #file(path: string, file: LogFile): Promise<Bytes> {
    const bytes = new Uint8Array(await (await this.#get(path)).arrayBuffer());
    const out = this.tamper?.tile ? this.tamper.tile(file, bytes) : bytes;
    if (out === "error") throw new HttpError(this.url(path), 503);
    return out;
  }

  /** Fetches a hash tile, which must hold `width` hashes. Level 0 holds leaf hashes. */
  async hashTile({ path, width, index, level = 0 }: { path: string; width: number; index: number; level?: number }): Promise<Bytes> {
    const bytes = await this.#file(path, { kind: "hashes", level, index });
    if (bytes.length !== width * 32) throw new Error(`hash tile ${path} has the wrong size`);
    return bytes;
  }

  /** Fetches the entry bundle beside a level-0 tile, as served. */
  entryBundle({ entries, index }: { entries: string; index: number }): Promise<Bytes> {
    return this.#file(entries, { kind: "entries", index });
  }
}
