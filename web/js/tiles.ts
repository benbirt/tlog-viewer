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

export class LogClient {
  readonly #fetch: Fetch;

  /**
   * @param base URL prefix ending in "/".
   * @param signal Aborts every request the client has in flight or makes later.
   */
  constructor(readonly base: string, fetchFn: Fetch = (url, init) => fetch(url, init), readonly signal?: AbortSignal) {
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
    return (await this.#get(path, { cache: "no-store" })).text();
  }

  /** Fetches a file of the log: a tile or an entry bundle. */
  async bytes(path: string): Promise<Bytes> {
    return new Uint8Array(await (await this.#get(path)).arrayBuffer());
  }

  /** Fetches a hash tile, which must hold `width` hashes. */
  async hashTile({ path, width }: { path: string; width: number }): Promise<Bytes> {
    const bytes = await this.bytes(path);
    if (bytes.length !== width * 32) throw new Error(`hash tile ${path} has the wrong size`);
    return bytes;
  }
}
