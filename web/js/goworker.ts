// The worker that answers the page's questions of the verifier (see
// verifier.ts for the other end): it runs the WebAssembly module and calls
// the functions it exports.

import { verifierFromPage } from "./gowasm.js";

const post = (message: { id: number; reply?: unknown; error?: string }) =>
  (self as unknown as { postMessage(m: unknown): void }).postMessage(message);

const ready = verifierFromPage();
ready.catch((e: unknown) => post({ id: -1, error: `the verifier could not be loaded: ${e instanceof Error ? e.message : String(e)}` }));

self.addEventListener("message", (ev: MessageEvent<{ id?: number; fn: string; args: unknown[] }>) => {
  const { id, fn, args } = ev.data;
  if (id === undefined) return; // the module, for verifierFromPage
  ready.then((call) => post({ id, reply: call(fn, ...args) }))
    .catch((e: unknown) => post({ id, error: e instanceof Error ? e.message : String(e) }));
});
