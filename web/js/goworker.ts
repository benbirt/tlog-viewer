// The worker that hosts the verifier: the WebAssembly module built from
// //verifier by TinyGo. It loads the module once and then answers calls to the
// functions it exports (see verifier.ts for the other end).

interface GoRuntime {
  importObject: WebAssembly.Imports;
  run(instance: WebAssembly.Instance): Promise<void>;
}

const g = globalThis as unknown as Record<string, unknown>;
const post = (message: { id: number; reply?: string; error?: string }) =>
  (self as unknown as { postMessage(m: unknown): void }).postMessage(message);

const ready: Promise<void> = (async () => {
  // TinyGo's runtime script defines a global class, Go.
  await import(new URL("../wasm/tinygo_wasm_exec.js", import.meta.url).href);
  const go = new (g.Go as new () => GoRuntime)();
  const { instance } = await WebAssembly.instantiateStreaming(fetch(new URL("../wasm/verifier.wasm", import.meta.url)), go.importObject);
  void go.run(instance); // runs for as long as the worker lives
  for (let i = 0; !g.tlogReady; i++) {
    if (i > 500) throw new Error("the WebAssembly module did not start");
    await new Promise((r) => setTimeout(r, 10));
  }
})();
ready.catch((e: unknown) => post({ id: -1, error: `the verifier could not be loaded: ${e instanceof Error ? e.message : String(e)}` }));

self.addEventListener("message", (ev: MessageEvent<{ id: number; fn: string; args: unknown[] }>) => {
  const { id, fn, args } = ev.data;
  ready.then(() => {
    const f = g[fn];
    // Only the module's own functions, never anything else on the global.
    if (typeof f !== "function" || !/^tlog[A-Z]\w*$/.test(fn)) throw new Error(`no such verifier function: ${fn}`);
    post({ id, reply: (f as (...a: unknown[]) => string)(...args) });
  }).catch((e: unknown) => post({ id, error: e instanceof Error ? e.message : String(e) }));
});
