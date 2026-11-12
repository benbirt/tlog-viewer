// A worker that fetches and checks entry bundles (ingest.ts) off the main
// thread, with its own instance of the verifier to split and hash them. Requests and replies are plain data; see pool.ts for the other end.

import type { Bytes } from "./bytes.js";
import { faultById } from "./faults.js";
import { checkBundle, type CheckedEntry } from "./ingest.js";
import { verifierFromPage } from "./gowasm.js";
import { HttpError, LogClient } from "./tiles.js";
import { type TileRef, verifierOver } from "./verifier.js";

export type WorkerRequest = { op: "bundle"; base: string; fault: string | null; tile: TileRef; from: number; size: number; tileLeafHashes: Bytes };

export type WorkerResult = CheckedEntry[];

/** An error in a form that survives being posted between threads. */
export interface WorkerError {
  message: string;
  /** Set for a failed HTTP request, so the page can tell a missing tile from other failures. */
  http?: { url: string; status: number };
}

export type WorkerReply = { id: number; result: WorkerResult } | { id: number; error: WorkerError };

const go = verifierFromPage();
const verifier = verifierOver(async (fn, ...args) => (await go)(fn, ...args));

async function handle(req: WorkerRequest): Promise<WorkerResult> {
  const fault = faultById(req.fault);
  const client = new LogClient(req.base, undefined, undefined, fault ?? undefined);
  return checkBundle(client, verifier, req.tile, req.from, req.size, req.tileLeafHashes, fault);
}

const post = (reply: WorkerReply) => (self as unknown as { postMessage(m: unknown): void }).postMessage(reply);

self.addEventListener("message", (ev: MessageEvent<{ id?: number; request: WorkerRequest }>) => {
  const { id, request } = ev.data;
  if (id === undefined) return; // the module, for verifierFromPage
  handle(request).then(
    (result) => post({ id, result }),
    (e: unknown) => post({
      id,
      error: {
        message: e instanceof Error ? e.message : String(e),
        ...(e instanceof HttpError ? { http: { url: e.url, status: e.status } } : {}),
      },
    }));
});
