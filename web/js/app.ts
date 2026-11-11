// The viewer UI. All data from the log is rendered as text nodes; nothing
// fetched is ever interpreted as markup.

import { b64Encode, type Bytes, bytesEqual, hex } from "./bytes.js";
import { logBaseUrl } from "./config.js";
import { type DecodedEntry, decodeEntry, type Summary } from "./entry.js";
import { type Fault, faultById, FAULTS, faultTargets, faultyFetch } from "./faults.js";
import { extendLeafHashes } from "./grow.js";
import { verifyInteriorTiles } from "./interior.js";
import { leafHash, rootFromLeafHashes } from "./merkle.js";
import { type CheckpointResult, type SignatureResult, verifyCheckpoint } from "./note.js";
import { logOrigins, parsePolicy, type QuorumNode } from "./policy.js";
import { POLICY_SOURCE, POLICY_TEXT } from "./policy_data.js";
import { HttpError, LogClient, TILE_WIDTH, tilePath, type TileRef, tilesForSize } from "./tiles.js";

const DEFAULT_PAGE_SIZE = 50;
/** A checkpoint last witnessed longer ago than this draws a warning. */
const STALE_AFTER_SECONDS = 24 * 60 * 60;
const policy = parsePolicy(POLICY_TEXT);
const origins = logOrigins(policy);

/** A decoded entry plus what the viewer established about its place in the log. */
interface Entry extends DecodedEntry {
  index: number;
  leafHash: Bytes;
  /** Whether the entry hashes to the leaf the log committed to. */
  inLog: boolean;
  /** Whether every check passed. */
  ok: boolean;
  /** Lower-cased text the search box matches against. */
  haystack: string;
}

/** Everything known about the log on screen; replaced wholesale on switching logs. */
interface LogState {
  origin: string;
  /** The simulated failure this load ran under, by id. */
  fault: string | null;
  /** Cancels the requests of a load that has been superseded. */
  abort: AbortController;
  client: LogClient;
  size: number;
  /** Set once the leaf hashes have been shown to hash to the checkpoint. */
  leafHashes: Bytes | null;
  entries: (Entry | undefined)[];
  loaded: number;
  failures: { leaf: number; parse: number; contentHash: number; signature: number };
  publishers: Set<string>;
  /** Indices of the entries passing the current filter, newest first. */
  view: number[];
  /** Whether every entry of the tree in hand has been checked. */
  done: boolean;
  /** The signed checkpoint in hand, as served, and what verifying it found. */
  checkpointRaw: string | null;
  result: CheckpointResult | null;
  /** A check for a newer checkpoint is under way. */
  refreshing: boolean;
  /** The log has contradicted itself; see reportInconsistency. */
  inconsistent: boolean;
  /** Loading stopped on an error, so entries not yet loaded will not be. */
  failed: boolean;
}

type StepId = "step-log" | "step-quorum" | "step-root" | "step-entries";
const STEPS: StepId[] = ["step-log", "step-quorum", "step-root", "step-entries"];

let state: LogState | null = null;

// ---------------------------------------------------------------------------
// DOM helpers

function $<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`missing element #${id}`);
  return el as T;
}

type Child = Node | string | null | undefined;

function h<K extends keyof HTMLElementTagNameMap>(
  tag: K, attrs?: Record<string, string> | null, ...children: Child[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) el.setAttribute(k, v);
  el.append(...children.filter((c): c is Node | string => c != null));
  return el;
}

const EXTERNAL = { rel: "noopener noreferrer", target: "_blank" };
const badge = (text: string, kind = "") => h("span", { class: `badge ${kind}` }, text);
/** A badge that is only a symbol, with the words a screen reader should say. */
const iconBadge = (symbol: string, kind: string, label: string) =>
  h("span", { class: `badge ${kind}`, role: "img", "aria-label": label }, symbol);
const checkBadge = (ok: boolean | null) =>
  ok === true ? iconBadge("✓", "ok", "Passed") : ok === false ? iconBadge("✕", "bad", "Failed") : iconBadge("?", "warn", "Not checked");
const mono = (text: string) => h("span", { class: "mono" }, text);
const link = (url: string, text = url) => h("a", { href: url, ...EXTERNAL }, text);
/** A link only when the text is an https URL; plain text otherwise. */
const maybeLink = (text: string): Child => (/^https:\/\/[^\s]+$/.test(text) ? link(text) : text);
const count = (n: number) => n.toLocaleString("en");

function kv(pairs: [string, Child][]): HTMLElement {
  return h("dl", { class: "kv" }, ...pairs
    .filter(([, v]) => v != null && v !== "")
    .flatMap(([k, v]) => [h("dt", null, k), h("dd", null, v)]));
}

const fmtTime = (iso: string | null) => (iso ? iso.replace("T", " ").replace(/(:\d\d)(\.\d+)?Z$/, "$1") : "—");

/** The latest Unix time, in seconds, that a Date can represent. */
const MAX_UNIX_SECONDS = 8_640_000_000_000n;

/** Formats Unix seconds from a signature, which may hold any 64-bit value. */
function fmtUnix(s: bigint): string {
  if (s <= 0n || s > MAX_UNIX_SECONDS) return `${s} (not a plausible time)`;
  return new Date(Number(s) * 1000).toISOString().replace("T", " ").replace(".000Z", " UTC");
}

/** How long ago a Unix time was, in words. */
function fmtAge(s: bigint, at: number): string {
  if (s <= 0n || s > MAX_UNIX_SECONDS) return "at an implausible time";
  const seconds = Math.round(at / 1000 - Number(s));
  if (seconds < -120) return "in the future";
  if (seconds < 90) return "just now";
  const units: [number, string][] = [[86400, "day"], [3600, "hour"], [60, "minute"]];
  for (const [size, name] of units) {
    const n = Math.floor(seconds / size);
    if (n >= 1) return `${count(n)} ${name}${n === 1 ? "" : "s"} ago`;
  }
  return "just now";
}

// ---------------------------------------------------------------------------
// Routing

/**
 * Everything about what the page is showing, all of it held in the URL
 * fragment so that any view can be linked to, reloaded, and stepped through
 * with the back button.
 */
interface Route {
  origin: string;
  /** The entry whose drawer is open. */
  entry: number | null;
  /** Search text. */
  q: string;
  validity: Validity | "";
  publisher: string;
  /** Show only entries that failed a check. */
  problems: boolean;
  /** Page of the filtered list, counting from zero. */
  page: number;
  pageSize: number;
  /** Whether the checkpoint panel is open. */
  checkpoint: boolean;
  /** The simulated failure in effect, by id. */
  fault: string | null;
}

const PAGE_SIZES = [25, 50, 100, 250];
const VALIDITIES: readonly string[] = ["current", "expired", "future", "unknown"];

function readRoute(): Route {
  const p = new URLSearchParams(location.hash.slice(1));
  const number = (key: string): number | null => {
    const v = p.get(key);
    return v !== null && /^\d{1,15}$/.test(v) ? Number(v) : null;
  };
  const log = p.get("log");
  const validity = p.get("validity") ?? "";
  const pageSize = number("per");
  return {
    origin: log !== null && origins.includes(log) ? log : origins[0] ?? "",
    entry: number("entry"),
    q: p.get("q") ?? "",
    validity: VALIDITIES.includes(validity) ? (validity as Validity) : "",
    publisher: p.get("publisher") ?? "",
    problems: p.get("problems") === "1",
    page: Math.max(0, (number("page") ?? 1) - 1),
    pageSize: pageSize !== null && PAGE_SIZES.includes(pageSize) ? pageSize : DEFAULT_PAGE_SIZE,
    checkpoint: p.get("checkpoint") === "1",
    fault: faultById(p.get("fault"))?.id ?? null,
  };
}

/** The fragment for a route; anything at its default is left out. */
function href(r: Route): string {
  const p = new URLSearchParams({ log: r.origin });
  if (r.q) p.set("q", r.q);
  if (r.validity) p.set("validity", r.validity);
  if (r.publisher) p.set("publisher", r.publisher);
  if (r.problems) p.set("problems", "1");
  if (r.page > 0) p.set("page", String(r.page + 1));
  if (r.pageSize !== DEFAULT_PAGE_SIZE) p.set("per", String(r.pageSize));
  if (r.checkpoint) p.set("checkpoint", "1");
  if (r.entry !== null) p.set("entry", String(r.entry));
  if (r.fault) p.set("fault", r.fault);
  return "#" + p.toString().replaceAll("%2F", "/");
}

/** A log's default view, keeping any simulated failure in effect. */
const logRoute = (origin: string): Route => ({
  origin, entry: null, q: "", validity: "", publisher: "", problems: false,
  page: 0, pageSize: ui.pageSize, checkpoint: false, fault: ui.fault,
});

/** The route on screen. Changes to it go through navigate(). */
let ui: Route = readRoute();

/**
 * Moves to a changed route and records it in the URL. A step worth returning
 * to with the back button (a page, the drawer) adds a history entry; an
 * adjustment (typing in the search box) replaces the current one.
 */
function navigate(change: Partial<Route>, history_: "push" | "replace"): void {
  ui = { ...ui, ...change };
  if (history_ === "push") history.pushState(null, "", href(ui));
  else history.replaceState(null, "", href(ui));
}

/** Makes the controls show the route, after it changed other than through them. */
function syncControls(): void {
  $<HTMLInputElement>("q").value = ui.q;
  $<HTMLSelectElement>("f-validity").value = ui.validity;
  $<HTMLSelectElement>("f-publisher").value = ui.publisher;
  $<HTMLInputElement>("f-problems").checked = ui.problems;
  $<HTMLSelectElement>("page-size").value = String(ui.pageSize);
  $<HTMLDetailsElement>("checkpoint").open = ui.checkpoint;
}

/** The time the page takes it to be: now, unless a simulated failure moves it. */
const now = (): number => Date.now() + (faultById(ui.fault)?.clockOffsetMs ?? 0);

// ---------------------------------------------------------------------------
// Status display

function setStep(id: StepId, stepState: "" | "busy" | "ok" | "warn" | "fail", text: string): void {
  const el = $(id);
  el.dataset.state = stepState;
  el.querySelector("p")!.textContent = text;
}

function notice(text: string | null, bad = false): void {
  const el = $("notice");
  el.className = text ? `notice${bad ? " bad" : ""}` : "";
  el.textContent = text ?? "";
}

async function pool<T>(items: T[], limit: number, fn: (item: T) => Promise<void>): Promise<void> {
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) await fn(items[next++]!);
  }));
}

// ---------------------------------------------------------------------------
// Loading and verifying a log

function markCurrentLog(origin: string): void {
  for (const a of $("logs").children) {
    if ((a as HTMLElement).dataset.origin === origin) {
      a.setAttribute("aria-current", "page");
      // On narrow screens the tabs scroll sideways; keep the current one in view.
      a.scrollIntoView({ block: "nearest", inline: "nearest" });
    } else {
      a.removeAttribute("aria-current");
    }
  }
}

/** Set while load() closes the entry drawer, so that doing so keeps the URL. */
let closingForReload = false;

async function load(origin: string, attempt = 0): Promise<void> {
  // Stop whatever the previous load still has in flight.
  state?.abort.abort();
  const abort = new AbortController();
  const fault = faultById(ui.fault);
  const base = logBaseUrl(origin);
  const s: LogState = {
    origin,
    fault: fault?.id ?? null,
    abort,
    client: new LogClient(base, fault ? faultyFetch(fault, base) : undefined, abort.signal),
    size: 0,
    leafHashes: null,
    entries: [],
    loaded: 0,
    failures: { leaf: 0, parse: 0, contentHash: 0, signature: 0 },
    publishers: new Set(),
    view: [],
    done: false,
    checkpointRaw: null,
    result: null,
    refreshing: false,
    inconsistent: false,
    failed: false,
  };
  state = s;
  const live = () => state === s;
  renderDebug(fault);

  markCurrentLog(origin);
  for (const id of STEPS) setStep(id, "", "Waiting…");
  $("cp-summary").textContent = "";
  $("cp-body").replaceChildren();
  $("entries").hidden = true;
  $<HTMLSelectElement>("f-publisher").length = 1;
  notice(null);
  // An open entry drawer shows checks from the previous load. Close it until
  // this load has verified the log again; the entry stays in the URL, so the
  // drawer reopens then.
  const dialog = $<HTMLDialogElement>("detail");
  if (dialog.open) {
    closingForReload = true;
    dialog.close();
  }
  $("detail-body").replaceChildren();
  $("checked").textContent = "";

  try {
    // 1 and 2: the checkpoint must satisfy the policy.
    setStep("step-log", "busy", "Fetching checkpoint…");
    let raw: string;
    try {
      raw = await fetchCheckpoint(s);
    } catch (e) {
      if (!live()) return;
      if (e instanceof HttpError && e.status === 404) {
        setStep("step-log", "warn", "No checkpoint published.");
        for (const id of STEPS.slice(1)) setStep(id, "", "Nothing to check.");
        notice(`${origin} is in the trust policy, but nothing is published at ${s.client.url("checkpoint")} yet.`);
        return;
      }
      throw e;
    }
    const result = await verifyFetched(s, raw);
    if (!live()) return;
    const cp = result.checkpoint;
    s.size = cp.size;
    s.checkpointRaw = raw;
    s.result = result;
    renderCheckpoint(s, result);
    if (!showCheckpointSteps(s, result)) return;

    // 3: every leaf hash, from the level-0 tiles, must hash up to the
    // checkpoint's root. This binds the whole log, not just one entry.
    const tiles = tilesForSize(cp.size);
    setStep("step-root", "busy", `Fetching ${tiles.length} hash tile${tiles.length === 1 ? "" : "s"}…`);
    const leafHashes = new Uint8Array(cp.size * 32);
    await pool(tiles, 6, async (t) => {
      if (live()) leafHashes.set(await s.client.hashTile(t), t.index * TILE_WIDTH * 32);
    });
    if (!live()) return;
    const root = await rootFromLeafHashes(leafHashes, cp.size);
    if (!live()) return;
    if (!bytesEqual(root, cp.hash)) {
      setStep("step-root", "fail", `Recomputed ${b64Encode(root)}, checkpoint says ${b64Encode(cp.hash)}.`);
      skipSteps(3);
      notice("The log's tiles do not hash to the witnessed checkpoint, so its contents are not shown.", true);
      return;
    }
    setStep("step-root", "busy", `${rootText(cp.size)} Checking interior tiles…`);
    // The viewer never relies on the log's tiles above level 0, but a log that
    // serves ones inconsistent with its leaves is broken, so check them too.
    const interior = await verifyInteriorTiles(s.client, leafHashes, cp.size);
    if (!live()) return;
    showRootStep(cp.size, interior);
    s.leafHashes = leafHashes;

    // 4: entries, newest first, each checked against its leaf hash.
    s.entries = new Array<Entry | undefined>(cp.size);
    $("entries").hidden = false;
    updateEntriesStep(s);
    applyFilter();
    openDetailFromRoute();
    await pool(tiles.toReversed(), 4, (t) => ingestBundle(s, t, 0));
    if (!live()) return;
    s.done = true;
    updateEntriesStep(s);
    applyFilter();
    openDetailFromRoute();
    markChecked(true);
  } catch (e) {
    if (!live()) return;
    // A partial tile is replaced as the log grows; if ours has gone, the
    // checkpoint we started from is stale. Start again from a fresh one.
    if (e instanceof HttpError && e.status === 404 && /\.p\/\d+$/.test(e.url) && attempt < 2) {
      return load(origin, attempt + 1);
    }
    console.error(e);
    notice(`Could not load ${origin}: ${e instanceof Error ? e.message : String(e)}`, true);
    s.failed = true;
    renderRows(); // rows still waiting for their entries now say so
    for (const id of STEPS) {
      if ($(id).dataset.state === "busy") setStep(id, "fail", "Failed.");
    }
  }
}

/** Marks the steps from `from` on as not reached. */
function skipSteps(from: number): void {
  for (const id of STEPS.slice(from)) setStep(id, "", "Not checked.");
}

function fetchCheckpoint(s: LogState): Promise<string> {
  // The "wrong log" simulation serves a different log's checkpoint.
  const other = faultById(s.fault)?.checkpointFromOtherLog ? origins.find((o) => o !== s.origin) : undefined;
  return (other ? new LogClient(logBaseUrl(other), undefined, s.abort.signal) : s.client).checkpoint();
}

function verifyFetched(s: LogState, raw: string): Promise<CheckpointResult> {
  return verifyCheckpoint(policy, raw, {
    expectedOrigin: s.origin,
    disabledAlgs: new Set(faultById(s.fault)?.disabledAlgs),
  });
}

/**
 * Shows the outcome of the two checkpoint steps, and says why if the
 * checkpoint is rejected. Returns whether the log's contents may be shown.
 */
function showCheckpointSteps(s: LogState, result: CheckpointResult): boolean {
  const cp = result.checkpoint;
  if (cp.origin !== s.origin) {
    setStep("step-log", "fail", `The checkpoint served is for ${cp.origin}, not ${s.origin}.`);
    skipSteps(1);
    notice("The checkpoint is for a different log, so the log's contents are not shown.", true);
    return false;
  }

  // A signature that fails beside ones that pass does not reject the
  // checkpoint, but it is never shown as a clean pass either.
  const logSigs = result.signatures.filter((x) => x.role === "log");
  const logAlgs = (status: SignatureResult["status"]) =>
    logSigs.filter((x) => x.status === status).map((x) => x.algName).join(" + ");
  const logUnsupportedOnly = !result.logSigned && logAlgs("unsupported") !== "" && logAlgs("invalid") === "";
  if (result.logSigned) {
    setStep("step-log", logAlgs("invalid") ? "warn" : "ok", `Signed by the log (${logAlgs("valid")})` +
      (logAlgs("invalid") ? `; its ${logAlgs("invalid")} signature is invalid` : "") +
      (logAlgs("unsupported") ? `; ${logAlgs("unsupported")} not supported by this browser` : "") + ".");
  } else if (logUnsupportedOnly) {
    setStep("step-log", "fail", `The log signs with ${logAlgs("unsupported")} only, which this browser cannot verify.`);
  } else {
    setStep("step-log", "fail", logSigs.length > 0
      ? "The log's signature is invalid."
      : "Not signed by any log key in the policy.");
  }

  const q = result.quorum;
  const witnessSigs = result.signatures.filter((x) => x.role === "witness");
  const cosigners = witnessSigs.filter((x) => x.status === "valid");
  const invalid = witnessSigs.filter((x) => x.status === "invalid").length;
  const unchecked = witnessSigs.filter((x) => x.status === "unsupported").length;
  // A checkpoint the witnesses have not seen for a day may not be the
  // log's latest: someone serving an old one would look like this.
  const witnessed = result.witnessedAt;
  const stale = witnessed !== null && now() / 1000 - Number(witnessed) > STALE_AFTER_SECONDS;
  const rule = q.kind === "group" ? `${q.count} of ${q.children.length} in “${q.name}”, ${q.threshold} required` : q.name;
  const quorumBlockedByBrowser = !q.satisfied && result.quorumPossible;
  setStep("step-quorum", !q.satisfied ? "fail" : invalid > 0 || stale ? "warn" : "ok",
    `${cosigners.length} valid cosignature${cosigners.length === 1 ? "" : "s"}; ${rule}.` +
    (witnessed !== null ? ` Witnessed ${fmtAge(witnessed, now())}${stale ? ", which is more than a day: this may not be the log's latest checkpoint" : ""}.` : "") +
    (invalid > 0 ? ` ${invalid} cosignature${invalid === 1 ? " is" : "s are"} invalid.` : "") +
    (unchecked > 0 ? ` ${unchecked} could not be checked in this browser.` : "") +
    (quorumBlockedByBrowser ? " They would be enough to meet the quorum." : ""));

  if (!result.ok) {
    skipSteps(2);
    notice(logUnsupportedOnly || quorumBlockedByBrowser
      ? "This browser cannot verify ML-DSA-44 signatures, which this checkpoint depends on, so the log's contents are not shown. A current version of Chrome can."
      : `The checkpoint does not satisfy the trust policy (${result.problems.join("; ")}), so the log's contents are not shown.`, true);
    return false;
  }
  return true;
}

const rootText = (size: number) => `Recomputed from ${count(size)} leaf hashes; matches the checkpoint.`;

/** Shows the Merkle root step once the leaves match the checkpoint. */
function showRootStep(size: number, interior: { checked: number; mismatched: string[] }): void {
  if (interior.mismatched.length > 0) {
    setStep("step-root", "fail", `The leaf hashes match the checkpoint, but the log serves interior tiles that do not match them: ${interior.mismatched.join(", ")}.`);
    notice("The log is serving interior hash tiles that disagree with its own leaves. The entries below are still checked against the witnessed checkpoint.", true);
  } else {
    setStep("step-root", "ok", rootText(size) + (interior.checked === 0
      ? " The log is too small to have interior tiles."
      : ` The log's ${count(interior.checked)} interior tile${interior.checked === 1 ? " matches" : "s match"} too.`));
  }
}

/**
 * Fetches one entry bundle and checks and records its entries, skipping those
 * before `from`, which an earlier load already holds.
 */
async function ingestBundle(s: LogState, t: TileRef, from: number): Promise<void> {
  const live = () => state === s;
  const leafHashes = s.leafHashes;
  if (!live() || !leafHashes) return;
  const fault = faultById(s.fault);
  const bundle = await s.client.entryBundle(t);
  const altered = fault?.entry ? faultTargets(s.size) : [];
  for (const [i, served] of bundle.entries()) {
    const index = t.index * TILE_WIDTH + i;
    if (index < from) continue;
    // A simulated failure alters an entry either as served, before it is
    // compared with its leaf hash, or as if logged that way, after.
    const rewrite = fault?.entry && altered.includes(index) ? fault.entry : null;
    const bytes = rewrite && fault?.entryStage === "served" ? rewrite(served) : served;
    const lh = await leafHash(bytes);
    const decoded = await decodeEntry(rewrite && fault?.entryStage === "logged" ? rewrite(bytes) : bytes);
    if (!live()) return;
    const inLog = bytesEqual(lh, leafHashes.subarray(index * 32, index * 32 + 32));
    const e: Entry = {
      ...decoded,
      index,
      leafHash: lh,
      inLog,
      ok: inLog && !decoded.error && decoded.checks.contentHash === true && decoded.checks.signature === true,
      haystack: haystack(index, decoded),
    };
    if (!inLog) s.failures.leaf++;
    if (e.error) s.failures.parse++;
    else {
      if (e.checks.contentHash !== true) s.failures.contentHash++;
      if (e.checks.signature !== true) s.failures.signature++;
    }
    const publisher = e.summary?.publisher;
    if (publisher && !s.publishers.has(publisher)) {
      s.publishers.add(publisher);
      const select = $<HTMLSelectElement>("f-publisher");
      select.length = 1;
      select.append(...[...s.publishers].sort().map((p) => new Option(p, p)));
      // The route may name a publisher whose entries had not loaded yet.
      select.value = ui.publisher;
    }
    s.entries[index] = e;
    s.loaded++;
    // An entry opened by link shows as soon as it arrives, not at the end.
    if (index === ui.entry) openDetailFromRoute();
  }
  updateEntriesStep(s);
  scheduleFilter();
}

// ---------------------------------------------------------------------------
// Following the log as it grows

/** How often to look for a new checkpoint. */
const REFRESH_SECONDS = 60;
let lastChecked = 0;

function markChecked(ok: boolean, note?: string): void {
  if (ok) lastChecked = Date.now();
  $("checked").textContent = ok
    ? `Checked ${new Date().toLocaleTimeString()}${note ? `; ${note}` : ""}`
    : "Last check for updates failed; will retry";
}

/**
 * The log has shown two states that cannot both be true of an append-only
 * log. This is the misbehaviour transparency logs exist to expose, so it is
 * reported, not smoothed over, and the page stops following the log.
 */
function reportInconsistency(s: LogState, what: string): void {
  s.inconsistent = true;
  setStep("step-root", "fail", what);
  notice(`${what} A log may only ever add entries. The entries below are those verified against the earlier checkpoint; the page has stopped following this log.`, true);
  $("checked").textContent = "Stopped following";
}

/**
 * Looks for a newer checkpoint and, if the log has grown, verifies and adds
 * the new entries without reloading what is already held.
 *
 * The new tree must extend the old one. The leaf hashes already verified are
 * kept, not fetched again, so hashing them together with the new ones to the
 * new checkpoint's root shows that nothing published earlier has changed.
 */
async function refresh(): Promise<void> {
  const s = state;
  if (!s || !s.done || s.refreshing || s.inconsistent || !s.leafHashes || !s.result) return;
  const live = () => state === s;
  s.refreshing = true;
  let committed = false;
  try {
    const raw = await fetchCheckpoint(s);
    if (!live()) return;
    if (raw === s.checkpointRaw) {
      // Nothing new; the witnessed age shown still moves on.
      showCheckpointSteps(s, s.result);
      return markChecked(true);
    }
    const result = await verifyFetched(s, raw);
    if (!live()) return;
    // A checkpoint the policy rejects gets the full treatment of a fresh load.
    if (!result.ok) return void load(s.origin);

    const old = s.result.checkpoint;
    const cp = result.checkpoint;
    const sameTree = cp.size === old.size && bytesEqual(cp.hash, old.hash);
    if (cp.size < old.size) {
      // An older checkpoint than the one in hand. If it is an earlier state of
      // the same tree this is only staleness somewhere between the log and
      // here, and the newer one stands. If not, the log has forked.
      const earlier = await rootFromLeafHashes(s.leafHashes, cp.size);
      if (!live()) return;
      if (!bytesEqual(earlier, cp.hash)) {
        return reportInconsistency(s, `The log now presents a tree of ${count(cp.size)} entries that is not the first ${count(cp.size)} of the ${count(old.size)} verified before.`);
      }
      return markChecked(true, `was served an older checkpoint, of ${count(cp.size)} entries`);
    }
    if (cp.size === old.size && !sameTree) {
      return reportInconsistency(s, `The log now presents a different tree of the same ${count(cp.size)} entries: root ${b64Encode(cp.hash)}, where it was ${b64Encode(old.hash)}.`);
    }
    if (sameTree) {
      // The same tree, witnessed again.
      s.checkpointRaw = raw;
      s.result = result;
      renderCheckpoint(s, result);
      showCheckpointSteps(s, result);
      return markChecked(true);
    }

    const growth = await extendLeafHashes(s.client, s.leafHashes, old.size, cp.size);
    if (!live()) return;
    if (growth.kind === "rewritten") {
      return reportInconsistency(s, `The log now serves a different hash for entry ${count(growth.index)}, which it had already published.`);
    }
    const root = await rootFromLeafHashes(growth.leafHashes, cp.size);
    if (!live()) return;
    if (!bytesEqual(root, cp.hash)) {
      return reportInconsistency(s, `The log's new tree of ${count(cp.size)} entries does not extend the ${count(old.size)} verified before: with those kept, the root is ${b64Encode(root)}, but the new checkpoint says ${b64Encode(cp.hash)}.`);
    }
    const interior = await verifyInteriorTiles(s.client, growth.leafHashes, cp.size);
    if (!live()) return;

    // Verified: take up the new tree, then fetch the entries added to it.
    committed = true;
    s.done = false;
    s.size = cp.size;
    s.leafHashes = growth.leafHashes;
    s.entries.length = cp.size;
    s.checkpointRaw = raw;
    s.result = result;
    renderCheckpoint(s, result);
    showCheckpointSteps(s, result);
    showRootStep(cp.size, interior);
    updateEntriesStep(s);
    applyFilter();
    await pool(tilesForSize(cp.size).slice(Math.floor(old.size / TILE_WIDTH)), 4, (t) => ingestBundle(s, t, old.size));
    if (!live()) return;
    s.done = true;
    updateEntriesStep(s);
    applyFilter();
    markChecked(true);
  } catch (e) {
    if (!live()) return;
    // Half-way through taking up a new tree there is no tidy way back, so
    // start over. Otherwise leave what is shown alone and try again later:
    // a failed request, or a partial tile replaced as the log grew again.
    if (committed) return void load(s.origin);
    console.warn(e);
    markChecked(false);
  } finally {
    s.refreshing = false;
  }
}

function updateEntriesStep(s: LogState): void {
  const f = s.failures;
  if (s.size === 0) return setStep("step-entries", "ok", "The log is empty.");
  const progress = `${count(s.loaded)} of ${count(s.size)}`;
  if (f.leaf + f.parse + f.contentHash + f.signature > 0) {
    const parts = [
      f.leaf && `${f.leaf} not matching the log's leaf hash`,
      f.parse && `${f.parse} unparseable`,
      f.contentHash && `${f.contentHash} content hash mismatches`,
      f.signature && `${f.signature} bad signatures`,
    ].filter(Boolean);
    return setStep("step-entries", "fail", `${progress} checked: ${parts.join(", ")}.`);
  }
  if (!s.done) return setStep("step-entries", "busy", `${progress} checked…`);
  setStep("step-entries", "ok", `All ${count(s.size)} are in the tree, hash correctly and carry a valid signature.`);
}

// ---------------------------------------------------------------------------
// Checkpoint panel

const SIGNATURE_BADGE: Record<SignatureResult["status"], [string, string]> = {
  "valid": ["valid", "ok"],
  "invalid": ["invalid", "bad"],
  "unsupported": ["not checked", "warn"],
  "unknown-key": ["not in policy", ""],
};

function quorumTree(n: QuorumNode): HTMLElement {
  const label = n.kind === "group" ? `${n.name} — ${n.count} of ${n.children.length}, needs ${n.threshold}` : n.name;
  return h("li", null,
    h("span", { class: n.satisfied ? "sat" : "unsat" }, n.satisfied ? "✓ " : "○ "), label,
    n.kind === "group" ? h("ul", null, ...n.children.map(quorumTree)) : null);
}

function renderCheckpoint(s: LogState, result: CheckpointResult): void {
  const cp = result.checkpoint;
  $("cp-summary").textContent = `size ${cp.size} · ${b64Encode(cp.hash)}`;

  const rows = result.signatures.map((sig) => h("tr", null,
    h("td", null, sig.role === "log" ? "Log" : sig.role === "witness" ? `Witness ${sig.witness}` : "Unknown"),
    h("td", null, mono(sig.name)),
    h("td", null, mono(sig.keyId.toString(16).padStart(8, "0"))),
    h("td", null, sig.algName ?? "—"),
    h("td", null, sig.timestamp !== null ? fmtUnix(sig.timestamp) : "—"),
    h("td", null, badge(...SIGNATURE_BADGE[sig.status])),
  ));

  $("cp-body").replaceChildren(
    kv([
      ["Origin", mono(cp.origin)],
      ["Tree size", count(cp.size)],
      ["Root hash", mono(b64Encode(cp.hash))],
      ["Source", link(s.client.url("checkpoint"))],
    ]),
    h("section", null, h("h3", null, "Signatures"),
      h("div", { class: "scroll-x" }, h("table", { class: "sigs" },
        h("thead", null, h("tr", null,
          ...["Signer", "Key name", "Key ID", "Algorithm", "Cosigned at", "Status"].map((t) => h("th", null, t)))),
        h("tbody", null, ...rows)))),
    h("section", null, h("h3", null, "Quorum rule"),
      result.quorum.kind === "none"
        ? h("p", null, "The policy requires no cosignatures.")
        : h("ul", { class: "tree" }, quorumTree(result.quorum))),
    h("section", null, h("h3", null, "Checkpoint body"),
      // Exactly the text the signatures were checked over.
      h("pre", null, result.text),
      result.extensionsAuthenticated ? null : h("p", { class: "caveat" },
        "The lines after the root hash are not covered by any log signature this browser verified, " +
        "so whoever relayed the checkpoint could have changed them.")),
  );
}

// ---------------------------------------------------------------------------
// Entry list

function haystack(index: number, e: DecodedEntry): string {
  const s = e.summary;
  if (!s) return String(index);
  return [index, s.subjectName, s.subjectDigest, s.workload, s.version, s.publisher, s.artifact,
    e.keyFingerprint, ...s.claims.map((c) => c.type)].filter((x) => x != null).join("\n").toLowerCase();
}

/**
 * Where now falls relative to the validity period an endorsement claims. This
 * is the endorser's own statement about dates, not something verified, so it
 * is worded and coloured differently from the checks.
 */
type Validity = "current" | "expired" | "future" | "unknown";

function validity(summary: Summary | null, at = now()): Validity {
  const nb = Date.parse(summary?.notBefore ?? "");
  const na = Date.parse(summary?.notAfter ?? "");
  if (Number.isNaN(nb) || Number.isNaN(na)) return "unknown";
  if (at < nb) return "future";
  if (at > na) return "expired";
  return "current";
}

const VALIDITY_BADGE: Record<Validity, [string, string]> = {
  current: ["current", "plain"], expired: ["expired", ""], future: ["not yet", "warn"], unknown: ["unknown", "warn"],
};

let filterQueued = false;
function scheduleFilter(): void {
  if (filterQueued) return;
  filterQueued = true;
  setTimeout(() => { filterQueued = false; applyFilter(); }, 150);
}

function applyFilter(): void {
  const s = state;
  if (!s?.leafHashes) return;
  // Filters come from the route, not the controls: a publisher named in a
  // link has no menu option to select until one of its entries has loaded.
  const terms = ui.q.toLowerCase().split(/\s+/).filter(Boolean);
  const wantValidity = ui.validity;
  const wantPublisher = ui.publisher;
  const problemsOnly = ui.problems;
  const filtering = terms.length > 0 || wantValidity !== "" || wantPublisher !== "" || problemsOnly;
  const at = now();
  const view: number[] = [];
  for (let i = s.size - 1; i >= 0; i--) {
    const e = s.entries[i];
    if (!e) {
      if (!filtering) view.push(i);
      continue;
    }
    if (problemsOnly && e.ok) continue;
    if (wantPublisher && e.summary?.publisher !== wantPublisher) continue;
    if (wantValidity && validity(e.summary, at) !== wantValidity) continue;
    if (!terms.every((t) => e.haystack.includes(t))) continue;
    view.push(i);
  }
  s.view = view;
  $("count").textContent = filtering
    ? `${count(view.length)} of ${s.loaded < s.size ? count(s.loaded) + " loaded" : count(s.size)}`
    : `${count(s.size)} entries`;
  renderRows();
}

function rowFor(s: LogState, index: number): HTMLElement {
  const e = s.entries[index];
  const row = h("div", { class: "row", role: "row" });
  const cell = (cls: string, ...c: Child[]) => h("span", { class: cls, role: "cell" }, ...c);
  // The link sits in the first cell and is stretched over the row in CSS, so
  // the whole row is clickable while remaining a link to assistive technology.
  const open = cell("num", h("a", { href: href({ ...ui, entry: index }), "aria-label": `Entry ${index}` }, String(index)));
  if (!e) {
    row.classList.add("pending");
    if (s.failed) row.classList.add("unloaded");
    row.append(open, cell("rest", s.failed ? "Not loaded" : "Loading…"));
    return row;
  }
  const sm = e.summary;
  row.append(
    open,
    cell("date", fmtTime(sm?.issuedOn ?? null)),
    cell("", sm?.subjectName ?? (e.error ? "Unreadable entry" : "—")),
    cell("c-digest", sm?.subjectDigest ? sm.subjectDigest.slice(0, 12) + "…" : "—"),
    cell("c-workload", sm?.workload ?? "—", sm?.version ? h("span", { class: "sub" }, " · " + sm.version) : null),
    cell("c-publisher", sm?.publisher ?? "—"),
    cell("", badge(...VALIDITY_BADGE[validity(sm)])),
    cell("c-ok", checkBadge(e.ok)),
  );
  return row;
}

const pageCount = (s: LogState): number => Math.max(1, Math.ceil(s.view.length / ui.pageSize));

/** Renders the current page of the filtered list. */
function renderRows(): void {
  const s = state;
  const rows = $("rows");
  if (!s?.leafHashes) return;
  const size = ui.pageSize;
  const pages = pageCount(s);
  // While a filtered log is still loading it may not yet reach the page the
  // route names. Show the last page there is, without rewriting the route.
  const page = Math.min(ui.page, pages - 1);
  const start = page * size;
  const indices = s.view.slice(start, start + size);

  $("pager").hidden = s.view.length === 0;
  $("page-status").textContent =
    `Page ${count(page + 1)} of ${count(pages)} · ${count(start + 1)}–${count(start + indices.length)} of ${count(s.view.length)}`;
  $<HTMLButtonElement>("page-first").disabled = $<HTMLButtonElement>("page-prev").disabled = page === 0;
  $<HTMLButtonElement>("page-next").disabled = $<HTMLButtonElement>("page-last").disabled = page === pages - 1;

  if (indices.length === 0) {
    rows.replaceChildren(h("div", { class: "empty" }, s.size === 0 ? "This log has no entries yet." : "No entries match."));
    return;
  }
  // Entries are still arriving while the log loads; keep keyboard focus on a
  // row across the re-renders that causes.
  const focused = document.activeElement?.closest("#rows a")?.getAttribute("href");
  rows.replaceChildren(...indices.map((index) => rowFor(s, index)));
  if (focused) {
    [...rows.querySelectorAll("a")].find((a) => a.getAttribute("href") === focused)?.focus({ preventScroll: true });
  }
}

function goToPage(target: number): void {
  if (!state) return;
  navigate({ page: Math.max(0, Math.min(target, pageCount(state) - 1)) }, "push");
  renderRows();
  // Bring the top of the new page into view if it has scrolled off.
  if ($("entries").getBoundingClientRect().top < 0) $("entries").scrollIntoView();
}

// ---------------------------------------------------------------------------
// Entry detail

function openDetailFromRoute(): void {
  const s = state;
  const { entry } = ui;
  const dialog = $<HTMLDialogElement>("detail");
  if (entry === null || !s?.leafHashes || entry >= s.size) {
    if (dialog.open) dialog.close();
    return;
  }
  $("detail-title").textContent = `Entry ${entry}`;
  const e = s.entries[entry];
  $("detail-body").replaceChildren(...(e ? detailSections(s, e) : [h("p", { class: "muted" }, "Loading…")]));
  if (!dialog.open) dialog.showModal();
}

function detailSections(s: LogState, e: Entry): HTMLElement[] {
  const sm = e.summary;
  const check = (ok: boolean | null, text: string) => h("li", null, checkBadge(ok), h("span", null, text));
  // Each check has three outcomes; say which, never implying a pass.
  const contentHashText = e.checks.contentHash === true
    ? "The recorded SHA-256 matches the statement."
    : e.checks.contentHash === false
      ? "The recorded SHA-256 does not match the statement."
      : "No SHA-256 of the statement could be checked: the entry records none, or could not be decoded.";
  const signatureText = e.checks.signature === true
    ? "The ECDSA P-256 signature over the statement verifies under the key below. Whether that key is one to trust is not checked: this page has no list of endorser keys."
    : e.checks.signature === false
      ? e.keyError
        ? `The signing key could not be read (${e.keyError}), so the signature verifies under nothing.`
        : "The signature over the statement does not verify under the key below."
      : e.keyPem
        ? "The signature could not be checked: the key is not ECDSA P-256."
        : "The signature was not checked: the entry could not be decoded.";
  const bundleIndex = Math.floor(e.index / TILE_WIDTH);
  const bundleWidth = Math.min(TILE_WIDTH, s.size - bundleIndex * TILE_WIDTH);
  const bundleUrl = s.client.url(tilePath("entries", bundleIndex, bundleWidth));

  const sections = [
    h("section", null, h("h3", null, "Verification"), h("ul", { class: "checks" },
      check(e.inLog, e.inLog
        ? `Leaf ${e.index} of the tree whose root the log signed and the witnesses cosigned.`
        : "This entry does not match the leaf hash the log committed to."),
      check(e.checks.contentHash, contentHashText),
      check(e.checks.signature, signatureText),
      e.error ? check(false, `Could not be decoded: ${e.error}`) : null,
    )),
  ];

  if (sm) {
    sections.push(
      h("section", null, h("h3", null, "Endorsement"), kv([
        ["Subject", sm.subjectName],
        ["SHA-256", sm.subjectDigest && mono(sm.subjectDigest)],
        ["Subjects", sm.subjectCount !== 1 ? `${sm.subjectCount} (first shown)` : null],
        ["Issued", fmtTime(sm.issuedOn)],
        ["Valid from", fmtTime(sm.notBefore)],
        ["Valid until", h("span", null, fmtTime(sm.notAfter) + " ", badge(...VALIDITY_BADGE[validity(sm)]))],
        ["Publisher", sm.publisher],
        ["Workload", sm.workload],
        ["Version", sm.version && mono(sm.version)],
        ["Artifact", sm.artifact],
        ["Predicate", sm.predicateType && maybeLink(sm.predicateType)],
      ])),
      h("section", null, h("h3", null, `Claims (${sm.claims.length})`), h("ul", { class: "claims" },
        ...sm.claims.map((c) => h("li", null, maybeLink(c.type),
          c.annotations && kv(Object.entries(c.annotations).map(
            ([k, v]): [string, Child] => [k, typeof v === "string" ? v : JSON.stringify(v)])))))),
    );
  }

  sections.push(
    h("section", null, h("h3", null, "Signing key"),
      kv([["SPKI SHA-256", e.keyFingerprint && mono(e.keyFingerprint)]]),
      e.keyPem ? h("pre", null, e.keyPem) : null),
    h("section", null, h("h3", null, "Log position"), kv([
      ["Leaf index", String(e.index)],
      ["Leaf hash", mono(hex(e.leafHash))],
      ["Entry bundle", link(bundleUrl)],
    ])),
  );
  if (e.statementText) {
    sections.push(h("section", null, h("h3", null, "Statement"), h("pre", null, e.statementText)));
  }
  if (e.recordText) {
    // Everything needed to re-check the entry by hand: its leaf hash is
    // SHA-256 of a zero byte followed by exactly this text.
    sections.push(h("details", { class: "raw" },
      h("summary", null, "Log entry as recorded"), h("pre", { class: "wrap" }, e.recordText)));
  }
  return sections;
}

// ---------------------------------------------------------------------------
// Wiring

/**
 * Shows which failure is being simulated, if any, and the menu for choosing
 * one. A simulation is always announced at the top of the page: a link that
 * turns one on must not be able to pass a faked failure off as a real one.
 */
function renderDebug(fault: Fault | null): void {
  const banner = $("debug-banner");
  banner.hidden = fault === null;
  if (fault) {
    banner.replaceChildren(
      h("strong", null, `Simulated failure: ${fault.title}. `),
      `${fault.description} The data is altered inside this page after it is fetched; the log itself is unaffected. `,
      h("a", { href: href({ ...ui, fault: null, entry: null }) }, "Stop simulating"));
  }
  const item = (id: string | null, title: string, description: string) => h("li", null,
    h("a", { href: href({ ...logRoute(ui.origin), fault: id }), ...(id === ui.fault ? { "aria-current": "true" } : {}) }, title),
    ` — ${description}`);
  $("debug-list").replaceChildren(
    item(null, "None", "Show the log as it is."),
    ...FAULTS.map((f) => item(f.id, f.title, f.description)));
}

function init(): void {
  $("policy-source").replaceChildren(
    mono(POLICY_SOURCE.target), " from ",
    link(`${POLICY_SOURCE.repo}/tree/${POLICY_SOURCE.commit}`, `google-tlog-witness@${POLICY_SOURCE.commit.slice(0, 7)}`));

  // Each control writes its value to the route; filtering then reads the route.
  const onFilter = (change: () => Partial<Route>) => () => {
    navigate({ ...change(), page: 0 }, "replace");
    applyFilter();
  };
  $("q").addEventListener("input", onFilter(() => ({ q: $<HTMLInputElement>("q").value })));
  $("f-validity").addEventListener("input", onFilter(() => ({ validity: $<HTMLSelectElement>("f-validity").value as Route["validity"] })));
  $("f-publisher").addEventListener("input", onFilter(() => ({ publisher: $<HTMLSelectElement>("f-publisher").value })));
  $("f-problems").addEventListener("input", onFilter(() => ({ problems: $<HTMLInputElement>("f-problems").checked })));
  $("page-size").addEventListener("input", onFilter(() => ({ pageSize: Number($<HTMLSelectElement>("page-size").value) })));
  $("page-first").addEventListener("click", () => goToPage(0));
  $("page-prev").addEventListener("click", () => goToPage(ui.page - 1));
  $("page-next").addEventListener("click", () => goToPage(ui.page + 1));
  $("page-last").addEventListener("click", () => goToPage(Infinity));
  $("refresh").addEventListener("click", () => void load(ui.origin));

  const checkpoint = $<HTMLDetailsElement>("checkpoint");
  checkpoint.addEventListener("toggle", () => {
    if (checkpoint.open === ui.checkpoint) return;
    navigate({ checkpoint: checkpoint.open }, "replace");
    renderRows(); // the rows' links carry the whole route
  });

  // Opening an entry goes through the route like every other control. The
  // rows are still real links, for opening in a new tab or copying.
  $("rows").addEventListener("click", (ev) => {
    const a = (ev.target as Element).closest("a");
    if (!a || ev.button !== 0 || ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey) return;
    const entry = new URLSearchParams(a.hash.slice(1)).get("entry");
    if (entry === null) return;
    ev.preventDefault();
    navigate({ entry: Number(entry) }, "push");
    openDetailFromRoute();
  });

  const dialog = $<HTMLDialogElement>("detail");
  dialog.addEventListener("close", () => {
    // Closed by load(), not by the reader: the entry stays in the URL.
    if (closingForReload) {
      closingForReload = false;
      return;
    }
    if (ui.entry !== null) navigate({ entry: null }, "push");
  });
  dialog.addEventListener("click", (ev) => { if (ev.target === dialog) dialog.close(); });

  // The URL changed other than through a control: a link was followed, or
  // the back button pressed.
  const onRoute = () => {
    ui = readRoute();
    syncControls();
    $("logs").replaceChildren(...origins.map((o) => h("a", { href: href(logRoute(o)), "data-origin": o }, o)));
    if (state?.origin !== ui.origin || state.fault !== ui.fault) {
      void load(ui.origin);
    } else {
      markCurrentLog(ui.origin);
      applyFilter();
      openDetailFromRoute();
    }
  };
  window.addEventListener("hashchange", onRoute);
  window.addEventListener("popstate", onRoute);
  onRoute();

  // Follow the log while the page is being looked at, and catch up when it
  // is looked at again.
  setInterval(() => { if (!document.hidden) void refresh(); }, REFRESH_SECONDS * 1000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && Date.now() - lastChecked > REFRESH_SECONDS * 1000) void refresh();
  });
}

init();
