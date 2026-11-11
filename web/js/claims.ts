// Titles for the claims an endorsement makes. A claim is identified by the
// URL of a document describing it; where that document is Markdown on GitHub,
// its first heading is fetched and shown beside the link. The titles are not
// part of the log and are not verified: they are whatever the linked
// document says today, which is why they are fetched rather than built in.

/** The raw-content URL of a claim document, if it is a Markdown file on GitHub. */
export function claimDocumentUrl(type: string): string | null {
  const m = /^https:\/\/github\.com\/([\w.-]+)\/([\w.-]+)\/blob\/([\w.-]+)\/([\w./-]+\.md)(?:[?#].*)?$/.exec(type);
  if (!m || m[4]!.split("/").some((part) => part === "" || part === "." || part === "..")) return null;
  return `https://raw.githubusercontent.com/${m[1]}/${m[2]}/${m[3]}/${m[4]}`;
}

/** The first top-level heading of a Markdown document, shortened if very long. */
export function titleOf(markdown: string): string | null {
  const line = markdown.split("\n").find((l) => /^# \S/.test(l));
  if (!line) return null;
  const title = line.slice(2).trim().replace(/\s+#+$/, "");
  return title.length > 100 ? title.slice(0, 99) + "…" : title;
}

const cache = new Map<string, Promise<string | null>>();

/** Resolves to a claim's title, or null if it has no document to read one from. Never rejects. */
export function claimTitle(type: string, fetchFn: (url: string) => Promise<Response> = (url) => fetch(url)): Promise<string | null> {
  const url = claimDocumentUrl(type);
  if (!url) return Promise.resolve(null);
  let title = cache.get(url);
  if (!title) {
    title = fetchFn(url).then((r) => (r.ok ? r.text() : null)).then((t) => (t === null ? null : titleOf(t))).catch(() => null);
    cache.set(url, title);
  }
  return title;
}
