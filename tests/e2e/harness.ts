// Runs the built site in a real browser against the made-up logs of
// testlog.ts. Nothing touches the network: the site, the policy module and
// the logs are all served by intercepting the browser's requests.

import { existsSync, readFileSync } from "node:fs";
import { delimiter, extname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Browser, type BrowserContext, chromium, type Page } from "playwright-core";
import type { Bytes } from "../../web/js/bytes.js";
import type { TestLog, World } from "./testlog.js";

export const SITE = "https://viewer.test/";
const siteDir = fileURLToPath(new URL("../../site/", import.meta.url));
const TYPES: Record<string, string> = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm" };

/** Finds Chrome: $CHROME_BIN, else the usual names on $PATH and in the usual places. */
function chromePath(): string {
  const names = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser"];
  const dirs = [
    ...(process.env.PATH ?? "").split(delimiter),
    "/usr/bin", "/usr/local/bin", "/run/current-system/sw/bin",
    ...(process.env.USER ? [`/etc/profiles/per-user/${process.env.USER}/bin`] : []),
    ...(process.env.HOME ? [join(process.env.HOME, ".nix-profile/bin")] : []),
  ];
  const candidates = [
    ...(process.env.CHROME_BIN ? [process.env.CHROME_BIN] : []),
    ...dirs.flatMap((d) => names.map((n) => join(d, n))),
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  ];
  const found = candidates.find((c) => c !== "" && existsSync(c));
  if (!found) throw new Error("No Chrome found for the browser tests. Install one, or set CHROME_BIN to its path.");
  return found;
}

export const launch = (): Promise<Browser> =>
  chromium.launch({
    executablePath: chromePath(),
    args: ["--no-sandbox", "--disable-gpu"],
    // Playwright hides scrollbars by default. A desktop browser shows them,
    // and they take up room, which is where layout bugs hide.
    ignoreDefaultArgs: ["--hide-scrollbars"],
  });

export interface StepState {
  state: string;
  text: string;
}

/** One browser tab on the viewer, and control over what the logs serve it. */
export class Viewer {
  /** What each log origin currently serves, by path. */
  private readonly served = new Map<string, Map<string, Bytes>>();
  /** Paths requested from logs since the last call to takeRequests(). */
  private requests: string[] = [];
  /** Titles served for claim documents, by URL. */
  readonly documents = new Map<string, string>();
  /** Errors the page raised or logged, for explaining a failed test. */
  readonly errors: string[] = [];

  private constructor(readonly context: BrowserContext, readonly page: Page, private readonly world: World) {}

  static async open(browser: Browser, world: World, options: { width?: number; height?: number } = {}): Promise<Viewer> {
    const context = await browser.newContext({ viewport: { width: options.width ?? 1280, height: options.height ?? 900 } });
    const page = await context.newPage();
    const v = new Viewer(context, page, world);
    page.on("pageerror", (e) => v.errors.push(e.message));
    page.on("console", (m) => { if (m.type() === "error") v.errors.push(m.text()); });
    await context.route("**/*", (route) => {
      const url = new URL(route.request().url());
      if (url.origin + "/" === SITE) {
        const path = url.pathname === "/" ? "/index.html" : url.pathname;
        if (path === "/js/policy_data.js") {
          const source = { repo: "https://example.com/policy", commit: "0".repeat(40), target: "//test:policy" };
          return route.fulfill({ contentType: "text/javascript", body:
            `export const POLICY_TEXT = ${JSON.stringify(world.policy)};\nexport const POLICY_SOURCE = ${JSON.stringify(source)};\n` });
        }
        const file = join(siteDir, path);
        if (!existsSync(file) || v.missing.has(path)) return route.fulfill({ status: 404, body: "not found" });
        return route.fulfill({ contentType: TYPES[extname(file)] ?? "application/octet-stream", body: readFileSync(file) });
      }
      const cors = { "access-control-allow-origin": "*" };
      if (url.hostname === "www.gstatic.com") {
        for (const [origin, files] of v.served) {
          const prefix = `/${origin}/`;
          if (!url.pathname.startsWith(prefix)) continue;
          const path = url.pathname.slice(prefix.length);
          v.requests.push(path);
          const body = files.get(path);
          return body
            ? route.fulfill({ headers: cors, contentType: "application/octet-stream", body: Buffer.from(body) })
            : route.fulfill({ status: 404, headers: cors, body: "not found" });
        }
        return route.fulfill({ status: 404, headers: cors, body: "not found" });
      }
      const document = v.documents.get(url.href);
      if (document !== undefined) return route.fulfill({ headers: cors, contentType: "text/plain", body: document });
      return route.abort();
    });
    await v.serve(world.main);
    await v.serve(world.empty);
    return v;
  }

  /** Makes a log serve its present state. */
  async serve(log: TestLog, options?: Parameters<TestLog["files"]>[0]): Promise<void> {
    this.served.set(log.origin, await log.files(options));
  }

  /** Changes one file a log serves. */
  alter(origin: string, path: string, edit: (bytes: Bytes) => Bytes): void {
    const files = this.served.get(origin)!;
    files.set(path, edit(files.get(path)!.slice()));
  }

  /** Paths of the site that are to be missing, such as "/wasm/verifier.wasm". */
  readonly missing = new Set<string>();

  takeRequests(): string[] {
    const out = this.requests;
    this.requests = [];
    return out;
  }

  /** Opens the viewer at a fragment such as "#log=…" and waits for it to finish loading the log. */
  async goto(fragment = ""): Promise<void> {
    await this.page.goto(SITE + fragment);
    await this.settled();
  }

  /** Waits until no step is in progress and the first has an outcome. */
  async settled(): Promise<void> {
    await this.page.waitForFunction(() => {
      const steps = [...document.querySelectorAll<HTMLElement>(".step")];
      return !!steps[0]!.dataset.state && !steps.some((s) => s.dataset.state === "busy") &&
        !document.querySelector("#rows .row.pending:not(.unloaded)");
    });
  }

  async steps(): Promise<{ log: StepState; quorum: StepState; root: StepState; entries: StepState }> {
    const all = await this.page.$$eval(".step", (els) => els.map((el) => ({
      state: (el as HTMLElement).dataset.state || "none",
      text: el.querySelector("p")!.textContent ?? "",
    })));
    return { log: all[0]!, quorum: all[1]!, root: all[2]!, entries: all[3]! };
  }

  /** The outcome of the four steps, as "log quorum root entries". */
  async outcome(): Promise<string> {
    const s = await this.steps();
    return [s.log, s.quorum, s.root, s.entries].map((x) => x.state).join(" ");
  }

  text(selector: string): Promise<string> {
    return this.page.locator(selector).innerText();
  }

  /** Waits for the entry drawer to be open or closed. */
  async drawer(open: boolean): Promise<void> {
    await this.page.waitForFunction((want) => document.querySelector<HTMLDialogElement>("#detail")!.open === want, open);
  }

  hash(): Promise<string> {
    return this.page.evaluate(() => location.hash);
  }

  /** The entry numbers of the rows on screen. */
  rows(): Promise<number[]> {
    return this.page.$$eval("#rows .row a", (els) => els.map((el) => Number(el.textContent)));
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}
