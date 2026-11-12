// Usage: gen_licenses <bundle.js>
// Writes to stdout the licence of every package whose code is in the bundle.
// esbuild marks each bundled file with a comment naming where it came from,
// so the list follows the bundle and cannot fall behind it.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const [bundlePath] = process.argv.slice(2);
if (!bundlePath) throw new Error("usage: gen_licenses <bundle.js>");

const packages = new Map<string, string>();
for (const m of readFileSync(bundlePath, "utf8").matchAll(/^\/\/ (node_modules\/\.aspect_rules_js\/[^/]+\/node_modules\/((?:@[^/]+\/)?[^/]+))\//gm)) {
  packages.set(m[2]!, m[1]!);
}
if (packages.size === 0) throw new Error("found no third-party packages in the bundle; has its format changed?");

const out: string[] = ["Third-party code included in this site (js/deps.js), with its licences.", ""];
for (const [name, dir] of [...packages].sort()) {
  if (!existsSync(dir)) throw new Error(`${name}: ${dir} is not available to read its licence from`);
  const version = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")).version as string;
  const file = readdirSync(dir).find((f) => /^licen[cs]e(\.(md|txt))?$/i.test(f));
  if (!file) throw new Error(`${name} has no licence file`);
  out.push("=".repeat(72), `${name} ${version}`, "=".repeat(72), "", readFileSync(join(dir, file), "utf8").trim(), "");
}
process.stdout.write(out.join("\n"));
