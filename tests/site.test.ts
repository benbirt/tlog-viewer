import assert from "node:assert/strict";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import test from "node:test";

// The compiled modules are served to browsers as they are, with no bundler to
// resolve imports. tsc is happy with `from "./bytes"`; a browser asks the
// server for exactly that and gets a 404. This checks the site as built, in
// which the one module with third-party imports has been bundled.
test("every import in the served modules names a file that exists", () => {
  const dir = new URL("../site/js/", import.meta.url);
  const modules = readdirSync(dir).filter((f) => f.endsWith(".js"));
  assert.ok(modules.includes("app.js"));
  assert.ok(modules.includes("policy_data.js"));
  assert.ok(modules.includes("deps.js"));
  assert.ok(modules.includes("worker.js"));
  let imports = 0;
  for (const file of modules) {
    const source = readFileSync(new URL(file, dir), "utf8");
    for (const m of source.matchAll(/^\s*(?:import|export)\b[^;]*?\bfrom\s+"([^"]+)"/gm)) {
      const specifier = m[1]!;
      assert.match(specifier, /^\.\/[\w.-]+\.js$/, `${file} imports "${specifier}"`);
      assert.ok(existsSync(new URL(specifier, new URL(file, dir))), `${file} imports missing "${specifier}"`);
      imports++;
    }
  }
  assert.ok(imports > 10);
});

test("the verifier is served where its worker looks for it, with its licences", () => {
  const site = new URL("../site/", import.meta.url);
  const worker = readFileSync(new URL("js/goworker.js", site), "utf8");
  const fetched = [...worker.matchAll(/new URL\("([^"]+)", import\.meta\.url\)/g)].map((m) => m[1]!);
  assert.deepEqual(fetched.sort(), ["../wasm/tinygo_wasm_exec.js", "../wasm/verifier.wasm"]);
  for (const f of fetched) assert.ok(existsSync(new URL(f, new URL("js/", site))), f);
  const notice = readFileSync(new URL("wasm/NOTICE.txt", site), "utf8");
  for (const name of ["transparency-dev/formats", "golang.org/x/mod", "filippo.io/mldsa", "Go standard library", "TinyGo"]) assert.ok(notice.includes(name), name);
  assert.match(readFileSync(new URL("index.html", site), "utf8"), /href="wasm\/NOTICE\.txt"/);
});
