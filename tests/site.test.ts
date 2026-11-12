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
