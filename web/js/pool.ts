// A small pool of workers (worker.ts) for the page to hand work to.

import type { Bytes } from "./bytes.js";
import type { CheckedEntry } from "./ingest.js";
import { HttpError, type TileRef } from "./tiles.js";
import type { WorkerReply, WorkerRequest, WorkerResult } from "./worker.js";

/** Thrown for work that was pending when its pool was shut down. */
export class Cancelled extends Error {
  constructor() {
    super("cancelled");
  }
}

interface Pending {
  resolve(result: WorkerResult): void;
  reject(e: Error): void;
}

export class WorkerPool {
  private readonly workers: { worker: Worker; busy: number }[] = [];
  private readonly pending = new Map<number, Pending>();
  private nextId = 0;

  constructor(size: number = Math.max(1, Math.min(4, navigator.hardwareConcurrency || 2))) {
    for (let i = 0; i < size; i++) {
      const slot = { worker: new Worker(new URL("./worker.js", import.meta.url), { type: "module" }), busy: 0 };
      slot.worker.addEventListener("message", (ev: MessageEvent<WorkerReply>) => {
        const p = this.pending.get(ev.data.id);
        if (!p) return;
        this.pending.delete(ev.data.id);
        slot.busy--;
        if ("result" in ev.data) return p.resolve(ev.data.result);
        const { message, http } = ev.data.error;
        p.reject(http ? new HttpError(http.url, http.status) : new Error(message));
      });
      slot.worker.addEventListener("error", (ev) => {
        // A worker that fails outright takes all its work with it.
        this.fail(new Error(`worker failed: ${ev.message || "could not be loaded"}`));
      });
      this.workers.push(slot);
    }
  }

  private run(request: WorkerRequest): Promise<WorkerResult> {
    const slot = this.workers.reduce((a, b) => (b.busy < a.busy ? b : a));
    const id = this.nextId++;
    slot.busy++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      slot.worker.postMessage({ id, request });
    });
  }

  private fail(e: Error): void {
    for (const p of this.pending.values()) p.reject(e);
    this.pending.clear();
  }

  /** Fetches and checks one entry bundle; see checkBundle. */
  bundle(args: { base: string; fault: string | null; tile: TileRef; from: number; size: number; tileLeafHashes: Bytes }): Promise<CheckedEntry[]> {
    return this.run({ op: "bundle", ...args });
  }

  /** Stops the workers at once, abandoning whatever they were doing. */
  terminate(): void {
    for (const { worker } of this.workers) worker.terminate();
    this.fail(new Cancelled());
  }
}
