import assert from "node:assert/strict";
import test from "node:test";
import { claimDocumentUrl, claimTitle, titleOf } from "../web/js/claims.js";

test("claim documents on GitHub map to their raw contents", () => {
  assert.equal(
    claimDocumentUrl("https://github.com/project-oak/oak/blob/main/docs/tr/claim/31543.md"),
    "https://raw.githubusercontent.com/project-oak/oak/main/docs/tr/claim/31543.md");
  // A query string distinguishes claims that share a document.
  assert.equal(
    claimDocumentUrl("https://github.com/project-oak/oak/blob/main/docs/tr/claim/31545.md?mpm_version_id=1-abc"),
    "https://raw.githubusercontent.com/project-oak/oak/main/docs/tr/claim/31545.md");
  for (const other of [
    "https://example.com/claims/1.md",
    "https://github.com/org/repo/blob/main/claim.txt",
    "https://github.com/org/repo/blob/main/../../other/repo/main/x.md",
    "https://github.com/org/repo/tree/main/docs",
    "http://github.com/org/repo/blob/main/x.md",
    "not a url",
  ]) assert.equal(claimDocumentUrl(other), null, other);
});

test("a document's title is its first top-level heading", () => {
  assert.equal(titleOf("<!-- comment -->\n\n# Publisher ID\n\nText.\n# Another\n"), "Publisher ID");
  assert.equal(titleOf("## Only a subheading\n#NoSpace\n"), null);
  assert.equal(titleOf("# " + "x".repeat(200)), "x".repeat(99) + "…");
});

test("titles are fetched once per document, and failures give no title", async () => {
  let fetched = 0;
  const fetchFn = async (url: string) => {
    fetched++;
    return url.endsWith("/a.md") ? new Response("# Claim A\n") : new Response("no", { status: 404 });
  };
  const a = "https://github.com/t/r/blob/main/a.md";
  assert.equal(await claimTitle(a, fetchFn), "Claim A");
  assert.equal(await claimTitle(a + "?v=2", fetchFn), "Claim A");
  assert.equal(fetched, 1);
  assert.equal(await claimTitle("https://github.com/t/r/blob/main/missing.md", fetchFn), null);
  assert.equal(await claimTitle("https://github.com/t/r/blob/main/broken.md", async () => { throw new Error("offline"); }), null);
  assert.equal(await claimTitle("https://example.com/x.md", fetchFn), null);
  assert.equal(fetched, 2);
});
