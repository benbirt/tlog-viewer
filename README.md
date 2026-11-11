# tlog-viewer

A static, single-page viewer for transparency logs that verifies what it shows.
Today it covers the PAIC logs
(`paic.google.com/log/N`, [tlog-tiles](https://c2sp.org/tlog-tiles)), whose
entries are Project Oak endorsements. Everything it shows is verified in the
browser with WebCrypto; there is no backend.

For the selected log it:

1. fetches the checkpoint and checks the log's signature (Ed25519 and
   ML-DSA-44) against the trust policy;
2. checks the witness cosignatures and evaluates the policy's quorum rule,
   warning if the quorum last saw the log in this state more than a day ago;
3. fetches every level-0 hash tile and recomputes the Merkle root, which must
   equal the witnessed checkpoint's, then checks that the interior hash tiles
   the log serves are the ones those leaves imply;
4. fetches the entry bundles and, for each entry, checks that it hashes to its
   leaf, that the recorded SHA-256 matches the embedded in-toto statement, and
   that the ECDSA signature over the statement verifies under the embedded key.

The viewer does not decide whether an endorsement's signing key is one to
trust: it has no list of endorser keys.

## Trust policy

The log keys, witness keys and quorum come from
[google-tlog-witness](https://github.com/google/google-tlog-witness): the
build takes `//policies/paic:prod-verifier` from the commit pinned in
`MODULE.bazel` and compiles it into `js/policy_data.js`. Logs are listed in the
UI straight from the policy, so a log added upstream appears once the pin
moves.

Because the pin moves without review, the build checks everything the viewer
will need from a policy: that the viewer's own parser accepts it, that every
key is well formed with the key ID its bytes imply, that each log has a key the
viewer can verify, and that the quorum can be met by witnesses it can verify.
A policy that would fail in the browser fails the build instead.

The policy names logs by origin only. Tile URLs follow the convention in
`web/js/config.ts` (`https://www.gstatic.com/<origin>/`); a log served
elsewhere needs a change there and in the `connect-src` of `web/index.html`.

## Working on it

    bazel test //...          # type-check, unit tests, and the browser tests
    bazel run //:serve        # http://127.0.0.1:8080/
    bazel build //:site       # static site in bazel-bin/site

The code is TypeScript, compiled file-for-file by `tsc` with no bundler and no
runtime dependencies. TypeScript and Node's types are the only npm packages;
change them with pnpm through Bazel (see `MODULE.bazel`).

- `web/js/policy.ts`, `note.ts`, `merkle.ts`, `tiles.ts`, `interior.ts`,
  `grow.ts`, `entry.ts` — the verifier, with no DOM dependencies.
- `web/js/app.ts` — the UI.
- `tests/e2e/` — the built site driven in a real browser (Playwright, with the
  Chrome already on the machine; set `CHROME_BIN` if it is not found). The logs
  it runs against are made up on each run, with their own keys, witnesses and
  policy, so they can grow, fork and misbehave on demand. Nothing is fetched
  from the network.
- `tests/testdata/` — a real checkpoint, tiles and entries captured from
  `paic.google.com/log/0`, with the policy as it stood then, so the tests keep
  passing when the pinned policy changes.

The page looks for a new checkpoint every minute while it is visible. When the
log has grown it fetches only the tiles that changed, checks that the new tree
extends the one already verified (the leaf hashes in hand are kept, and must
hash with the new ones to the new root), and adds the new entries. If the log
contradicts what it showed before, by changing a published leaf or presenting
a tree that is not an extension, the page says so and stops following it.

Everything about the view is kept in the address: the log, search and filters,
page, whether the checkpoint panel is open and which entry's drawer is open. Any
view can be linked to or reloaded, and Back steps through pages and drawers.

The footer has a debug menu that simulates failures (`web/js/faults.ts`): bad
log signatures and cosignatures, a missing quorum, another log's checkpoint, an
old checkpoint, a browser without ML-DSA-44, tiles that do not match, and
entries that are altered or bad. Each alters data inside the page after it is
fetched, so the real failure paths run; none can make a check pass, and a
simulation is always announced at the top of the page.

ML-DSA-44 needs a recent browser (Chrome 157 is known to work). Where WebCrypto
lacks it, those signatures are reported as not checked and the quorum is
evaluated on the remaining ones.

## Automation

Everything that can go stale is updated by pull requests that merge themselves
once CI passes:

| What | Updated by | When |
| --- | --- | --- |
| google-tlog-witness commit (the trust policy) | `update-pins.yaml` | daily |
| `.bazelversion` | `update-pins.yaml` | daily |
| Bazel modules (`bazel_dep` versions) | `update-pins.yaml` | daily |
| Node, within its major version | `update-pins.yaml` | daily |
| npm packages, GitHub Actions | Dependabot, merged by `dependabot-auto-merge.yaml` | weekly |

`pages.yaml` deploys on every push to `main`, which includes those merges.

The update workflows act with a personal token, the `AUTOMATION_TOKEN` secret,
because pushes and merges made with the built-in workflow token trigger no
other workflows: CI would not run on the pull requests, and the merges would
not be deployed.

### Repository settings this relies on

- Pages: source "GitHub Actions".
- General: "Allow auto-merge" on.
- A fine-grained personal access token for this repository with read and
  write access to Contents and Pull requests, saved as `AUTOMATION_TOKEN`
  under both Actions secrets and Dependabot secrets. It expires; when it
  does, the update workflows fail until it is replaced.
- A ruleset or branch protection on `main` that requires a pull request (with
  no required approvals, or the bots' pull requests will wait for one) and
  requires the status check `test`. Auto-merge needs at least one requirement
  to wait for; without the required check the update workflows fail rather
  than merge untested changes.

Note what the first row of the table means: whatever google-tlog-witness
publishes on `main` becomes the deployed viewer's trust policy within a day,
unreviewed here, provided this repository's tests pass.
