import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import type { Browser } from "playwright-core";
import { FAULTS } from "../../web/js/faults.js";
import { launch, Viewer } from "./harness.js";
import { buildWorld, PUBLISHERS, type World } from "./testlog.js";

// 300 entries: one full tile and a partial one, so the log has an interior
// tile, and six pages of fifty.
const SIZE = 300;

let browser: Browser;
let world: World;

before(async () => {
  [browser, world] = await Promise.all([launch(), buildWorld()]);
  await world.main.append(SIZE);
});
after(() => browser?.close());

/** Runs a test in a fresh tab, on a copy of the world it may change freely. */
function viewerTest(name: string, fn: (v: Viewer, w: World) => Promise<void>, options?: Parameters<typeof Viewer.open>[2]): void {
  test(name, async () => {
    const w = { ...world, main: world.main.fork() };
    const v = await Viewer.open(browser, w, options);
    try {
      await fn(v, w);
    } catch (e) {
      console.error(`page state at failure: ${await v.outcome().catch(() => "?")} | ${await v.text("#notice").catch(() => "?")}`);
      throw e;
    } finally {
      await v.close();
    }
  });
}

viewerTest("a healthy log verifies and is listed newest first", async (v) => {
  await v.goto();
  assert.equal(await v.outcome(), "ok ok ok ok");
  const s = await v.steps();
  assert.match(s.log.text, /Signed by the log \(Ed25519 \+ ML-DSA-44\)/);
  assert.match(s.quorum.text, /3 valid cosignatures; 3 of 3 in “two-of-three”, 2 required\. Witnessed (just now|\d+ minutes? ago)\./);
  assert.match(s.root.text, /Recomputed from 300 leaf hashes; matches the checkpoint\. The log's 1 interior tile matches too\./);
  assert.match(s.entries.text, /All 300 are in the tree/);
  assert.equal(await v.text("#count"), "300 entries");
  assert.deepEqual((await v.rows()).slice(0, 3), [299, 298, 297]);
  assert.equal((await v.rows()).length, 50);
  assert.match(await v.text("#checked"), /^Checked /);
  assert.equal(await v.page.locator("#debug-banner").isHidden(), true);
  assert.equal(await v.page.locator("#rows .badge.bad").count(), 0);
});

viewerTest("an empty log and an unpublished one are told apart", async (v, w) => {
  await v.goto(`#log=${w.empty.origin}`);
  assert.equal(await v.outcome(), "ok ok ok ok");
  assert.match((await v.steps()).entries.text, /The log is empty/);
  assert.match(await v.text("#rows"), /no entries yet/);

  await v.goto(`#log=${w.unpublished}`);
  assert.equal(await v.outcome(), "warn none none none");
  assert.match(await v.text("#notice"), /in the trust policy, but nothing is published/);
});

// What each simulated failure must show: the four steps' outcomes, and how
// many rows on the first page fail a check.
const FAULT_OUTCOMES: Record<string, [outcome: string, failedRows: number]> = {
  "log-signature": ["fail ok none none", 0],
  "one-log-signature": ["warn ok ok ok", 0],
  "witness-signature": ["ok warn ok ok", 0],
  "no-quorum": ["ok fail none none", 0],
  "wrong-log": ["fail none none none", 0],
  "stale-checkpoint": ["ok warn ok ok", 0],
  "no-ml-dsa": ["ok ok ok ok", 0],
  "leaf-hashes": ["ok ok fail none", 0],
  "interior-tile": ["ok ok fail ok", 0],
  "tile-unavailable": ["ok ok ok fail", 0],
  "entry-swapped": ["ok ok ok fail", 2],
  "entry-signature": ["ok ok ok fail", 2],
  "entry-content": ["ok ok ok fail", 2],
  "entry-key": ["ok ok ok fail", 2],
  "entry-garbage": ["ok ok ok fail", 2],
};

test("every simulated failure has an expected outcome", () => {
  assert.deepEqual(Object.keys(FAULT_OUTCOMES).sort(), FAULTS.map((f) => f.id).sort());
});

for (const fault of FAULTS) {
  viewerTest(`simulated failure: ${fault.title}`, async (v) => {
    await v.goto(`#log=test.example/log/0&fault=${fault.id}`);
    const [outcome, failedRows] = FAULT_OUTCOMES[fault.id]!;
    assert.equal(await v.outcome(), outcome);
    assert.equal(await v.page.locator("#rows .badge.bad").count(), failedRows);
    // A simulation is always announced.
    assert.match(await v.text("#debug-banner"), new RegExp(`Simulated failure: ${fault.title.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}`));
    // Where the log's contents may not be shown, they are not.
    if (/none$/.test(outcome)) assert.equal(await v.page.locator("#entries").isHidden(), true);
  });
}

viewerTest("the simulated failures say what went wrong", async (v) => {
  await v.goto("#log=test.example/log/0&fault=no-ml-dsa");
  const s = await v.steps();
  assert.match(s.log.text, /Signed by the log \(Ed25519\); ML-DSA-44 not supported by this browser/);
  assert.match(s.quorum.text, /2 valid cosignatures.*1 could not be checked in this browser/);

  await v.goto("#log=test.example/log/0&fault=stale-checkpoint");
  assert.match((await v.steps()).quorum.text, /Witnessed 3 days ago, which is more than a day/);

  await v.goto("#log=test.example/log/0&fault=entry-signature");
  await v.page.locator("#rows .row a").first().click();
  assert.match(await v.text("#detail-body"), /The signature over the statement does not verify under the key below/);
  assert.match(await v.text("#detail-body"), /The recorded SHA-256 matches the statement/);
});

viewerTest("everything about the view is in the address, and comes back from it", async (v, w) => {
  await v.goto();
  await v.page.fill("#q", "workload-2");
  await v.page.selectOption("#f-validity", "current");
  await v.page.selectOption("#f-publisher", PUBLISHERS[0]!);
  await v.page.selectOption("#page-size", "25");
  await v.page.click("#page-next");
  await v.page.click("#checkpoint > summary");
  const third = (await v.rows())[2]!;
  await v.page.locator("#rows .row a").nth(2).click();
  await v.drawer(true);

  const hash = await v.hash();
  const params = new URLSearchParams(hash.slice(1));
  assert.deepEqual(Object.fromEntries(params), {
    log: "test.example/log/0", q: "workload-2", validity: "current", publisher: PUBLISHERS[0]!,
    page: "2", per: "25", checkpoint: "1", entry: String(third),
  });
  const status = await v.text("#page-status");
  const rows = await v.rows();

  // A second tab given only the address shows the same thing.
  const other = await Viewer.open(browser, w);
  try {
    await other.goto(hash);
    assert.equal(await other.page.inputValue("#q"), "workload-2");
    assert.equal(await other.page.inputValue("#f-validity"), "current");
    assert.equal(await other.page.inputValue("#f-publisher"), PUBLISHERS[0]);
    assert.equal(await other.page.inputValue("#page-size"), "25");
    assert.equal(await other.text("#page-status"), status);
    assert.deepEqual(await other.rows(), rows);
    assert.equal(await other.page.locator("#checkpoint").getAttribute("open"), "");
    assert.equal(await other.text("#detail-title"), `Entry ${third}`);
    assert.equal(await other.hash(), hash);
  } finally {
    await other.close();
  }

  // Closing the drawer takes the entry out of the address; Back reopens it,
  // and Back again returns to the first page.
  await v.page.click("#detail .btn");
  await v.page.waitForFunction(() => !location.hash.includes("entry="));
  assert.equal(new URLSearchParams((await v.hash()).slice(1)).has("entry"), false);
  await v.page.goBack();
  await v.drawer(true);
  assert.equal(await v.text("#detail-title"), `Entry ${third}`);
  await v.page.goBack();
  await v.drawer(false);
  await v.page.goBack();
  assert.equal(new URLSearchParams((await v.hash()).slice(1)).has("page"), false);
});

viewerTest("the table pages through the whole log", async (v) => {
  await v.goto();
  assert.equal(await v.text("#page-status"), "Page 1 of 6 · 1–50 of 300");
  assert.equal(await v.page.locator("#page-prev").isDisabled(), true);
  await v.page.click("#page-next");
  assert.deepEqual((await v.rows()).slice(0, 2), [249, 248]);
  await v.page.click("#page-last");
  assert.equal(await v.text("#page-status"), "Page 6 of 6 · 251–300 of 300");
  assert.equal((await v.rows()).at(-1), 0);
  assert.equal(await v.page.locator("#page-next").isDisabled(), true);

  // Filters narrow the list and return to the first page.
  await v.page.selectOption("#f-validity", "expired");
  assert.match(await v.text("#count"), /^4[23] of 300$/);
  assert.match(await v.text("#page-status"), /^Page 1 of 1/);
  await v.page.selectOption("#f-validity", "");
  await v.page.fill("#q", "no such thing anywhere");
  assert.match(await v.text("#rows"), /No entries match/);
});

viewerTest("an entry's drawer shows its checks, its statement and the entry as recorded", async (v) => {
  await v.goto("#log=test.example/log/0&entry=123");
  await v.drawer(true);
  const body = await v.text("#detail-body");
  assert.match(body, /Leaf 123 of the tree whose root the log signed and the witnesses cosigned/);
  assert.match(body, /The recorded SHA-256 matches the statement/);
  assert.match(body, /verifies under the key below\. Whether that key is one to trust is not checked/);
  assert.match(body, /workload-3/);
  assert.match(body, /"predicateType": "https:\/\/project-oak\.github\.io\/oak\/tr\/endorsement\/v1"/);
  assert.match(body, /-----BEGIN PUBLIC KEY-----/);
  await v.page.click("#detail-body details.raw > summary");
  assert.match(await v.text("#detail-body details.raw pre"), /^\{"apiVersion":"0\.0\.1","kind":"hashedrekord"/);
});

viewerTest("the drawer does not outlive the log it was opened on", async (v, w) => {
  await v.goto("#log=test.example/log/0&entry=5");
  await v.drawer(true);
  await v.page.evaluate((o) => { location.hash = `#log=${o}&entry=5`; }, w.unpublished);
  await v.drawer(false);
  assert.equal(await v.outcome(), "warn none none none");
});

// Following the log as it changes. The page checks once a minute; the tests
// move its clock on rather than wait.
async function nextCheck(v: Viewer): Promise<void> {
  const before = await v.text("#checked");
  await v.page.clock.fastForward(61_000);
  await v.page.waitForFunction((b) => document.querySelector("#checked")!.textContent !== b, before);
  await v.settled();
}

viewerTest("a log that grows is followed, fetching only what changed", async (v, w) => {
  await v.page.clock.install();
  await v.goto();
  assert.equal(await v.text("#count"), "300 entries");
  v.takeRequests();

  await w.main.append(20);
  await v.serve(w.main);
  await nextCheck(v);
  assert.equal(await v.outcome(), "ok ok ok ok");
  assert.equal(await v.text("#count"), "320 entries");
  assert.deepEqual((await v.rows()).slice(0, 2), [319, 318]);
  assert.match((await v.steps()).root.text, /Recomputed from 320 leaf hashes/);
  // The first tile is full and cannot have changed: it is not asked for again.
  assert.deepEqual(v.takeRequests().sort(), ["checkpoint", "tile/0/001.p/64", "tile/1/000.p/1", "tile/entries/001.p/64"]);

  // Nothing new: only the checkpoint is fetched.
  await nextCheck(v);
  assert.deepEqual(v.takeRequests(), ["checkpoint"]);
  assert.equal(await v.text("#count"), "320 entries");
}, {});

viewerTest("a log that rewrites a published entry is reported and no longer followed", async (v, w) => {
  await v.page.clock.install();
  await v.goto();
  await w.main.rewrite(280);
  await w.main.append(5);
  await v.serve(w.main);
  await nextCheck(v);
  assert.equal(await v.outcome(), "ok ok fail ok");
  assert.match(await v.text("#notice"), /now serves a different hash for entry 280, which it had already published/);
  assert.equal(await v.text("#checked"), "Stopped following");
  assert.equal(await v.text("#count"), "300 entries");
});

viewerTest("a new tree that does not extend the old one is reported", async (v, w) => {
  await v.page.clock.install();
  await v.goto();
  // Entry 5 is in the first, full tile, which is not fetched again: only the
  // root can give this away.
  await w.main.rewrite(5);
  await w.main.append(5);
  await v.serve(w.main);
  await nextCheck(v);
  assert.equal(await v.outcome(), "ok ok fail ok");
  assert.match(await v.text("#notice"), /new tree of 305 entries does not extend the 300 verified before/);
});

viewerTest("a different tree of the same size is reported", async (v, w) => {
  await v.page.clock.install();
  await v.goto();
  await w.main.rewrite(299);
  await v.serve(w.main);
  await nextCheck(v);
  assert.match(await v.text("#notice"), /a different tree of the same 300 entries/);
  assert.equal(await v.text("#checked"), "Stopped following");
});

viewerTest("an older checkpoint of the same tree is noted and otherwise ignored", async (v, w) => {
  await v.page.clock.install();
  await v.goto();
  await v.serve(w.main.fork(280));
  await nextCheck(v);
  assert.equal(await v.outcome(), "ok ok ok ok");
  assert.match(await v.text("#checked"), /was served an older checkpoint, of 280 entries/);
  assert.equal(await v.text("#count"), "300 entries");
});

viewerTest("a checkpoint the policy rejects is shown as on a fresh visit", async (v, w) => {
  await v.page.clock.install();
  await v.goto();
  await w.main.append(1);
  await v.serve(w.main, { witnesses: 1 });
  await v.page.clock.fastForward(61_000);
  await v.page.waitForFunction(() => document.querySelector<HTMLElement>("#step-quorum")!.dataset.state === "fail");
  assert.equal(await v.outcome(), "ok fail none none");
  assert.equal(await v.page.locator("#entries").isHidden(), true);
});

viewerTest("a checkpoint not witnessed for a day draws a warning", async (v, w) => {
  await v.serve(w.main, { age: 2 * 86400 });
  await v.goto();
  assert.equal(await v.outcome(), "ok warn ok ok");
  assert.match((await v.steps()).quorum.text, /Witnessed 2 days ago, which is more than a day/);
});

viewerTest("nothing spills off a phone screen", async (v) => {
  await v.goto("#log=test.example/log/0&checkpoint=1");
  const overflow = () => v.page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  assert.equal(await overflow(), 0);
  // The header row has exactly as many visible cells as each row beneath it.
  const cells = (selector: string) => v.page.locator(selector).first().evaluate((row) =>
    [...row.children].filter((c) => getComputedStyle(c).display !== "none").length);
  assert.equal(await cells(".row.head"), await cells("#rows .row"));
  await v.page.locator("#rows .row a").first().click();
  await v.drawer(true);
  assert.equal(await overflow(), 0);
}, { width: 390, height: 844 });
