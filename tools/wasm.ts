// Runs the verifier (//verifier) in Node, for the build and the tests: the
// same WebAssembly module the page runs in a worker (web/js/goworker.ts).

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { type Call, type Verifier, verifierOver } from "../web/js/verifier.js";

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

/**
 * Starts a build of the verifier with the runtime script that goes with its
 * compiler, and returns a way to call it. More than one build can be loaded
 * into the same process.
 */
export async function loadWasm(wasm: string, exec: string): Promise<Call> {
  const g = globalThis as unknown as Record<string, unknown>;
  // Go's and TinyGo's runtime scripts each define a global class, Go.
  delete g.Go;
  await import(pathToFileURL(resolve(exec)).href);
  const go = new (g.Go as new () => GoRuntime)();
  delete g.Go;
  const { instance } = await WebAssembly.instantiate(readFileSync(resolve(wasm)), go.importObject);
  void go.run(instance); // runs for as long as the module serves calls
  for (let i = 0; !g.tlogReady; i++) {
    if (i > 500) throw new Error(`the WebAssembly module ${wasm} did not start`);
    await new Promise((r) => setTimeout(r, 10));
  }
  // Take the module's functions off the global, leaving it clear for another build.
  const fns = new Map<string, (...args: unknown[]) => string>();
  for (const name of Object.keys(g).filter((k) => /^tlog[A-Z]/.test(k))) {
    if (typeof g[name] === "function") fns.set(name, g[name] as (...args: unknown[]) => string);
    delete g[name];
  }
  return async (fn, ...args) => {
    const f = fns.get(fn);
    if (!f) throw new Error(`no such verifier function: ${fn}`);
    return f(...args);
  };
}

/** The verifier as the built site ships it, given the site's directory. */
export async function siteVerifier(site: URL): Promise<Verifier> {
  const file = (f: string) => fileURLToPath(new URL(f, site));
  return verifierOver(await loadWasm(file("wasm/verifier.wasm"), file("wasm/tinygo_wasm_exec.js")));
}
