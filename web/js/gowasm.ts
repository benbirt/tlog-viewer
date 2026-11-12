// Loading and running the verifier's WebAssembly module (built from
// //verifier by TinyGo). The page compiles it once and hands the compiled
// module to each worker that needs it; every worker runs its own instance.

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

/** Calls one of the module's functions. */
export type GoCall = (fn: string, ...args: unknown[]) => unknown;

/** In the page: fetches and compiles the module. */
export function compileVerifier(): Promise<WebAssembly.Module> {
  return WebAssembly.compileStreaming(fetch(new URL("../wasm/verifier.wasm", import.meta.url)));
}

/** In a worker: starts an instance of the module and returns a way to call it. */
export async function runVerifier(module: WebAssembly.Module): Promise<GoCall> {
  const g = globalThis as unknown as Record<string, unknown>;
  // TinyGo's runtime script defines a global class, Go.
  await import(new URL("../wasm/tinygo_wasm_exec.js", import.meta.url).href);
  const go = new (g.Go as new () => GoRuntime)();
  const instance = await WebAssembly.instantiate(module, go.importObject);
  void go.run(instance); // runs for as long as the worker lives
  for (let i = 0; !g.tlogReady; i++) {
    if (i > 500) throw new Error("the WebAssembly module did not start");
    await new Promise((r) => setTimeout(r, 10));
  }
  return (fn, ...args) => {
    const f = g[fn];
    // Only the module's own functions, never anything else on the global.
    if (typeof f !== "function" || !/^tlog[A-Z]\w*$/.test(fn)) throw new Error(`no such verifier function: ${fn}`);
    return (f as (...a: unknown[]) => unknown)(...args);
  };
}

/**
 * In a worker: waits for the page to post `{ module }`, then runs it. Other
 * messages are left for the worker's own handler.
 */
export function verifierFromPage(): Promise<GoCall> {
  return new Promise((resolve) => {
    self.addEventListener("message", (ev: MessageEvent<{ module?: WebAssembly.Module }>) => {
      if (ev.data.module) resolve(runVerifier(ev.data.module));
    });
  });
}
