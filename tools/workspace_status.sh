#!/usr/bin/env bash
# Bazel workspace status for stamped builds (bazel build --config=release):
# the commit the site is built from, and whether the tree had other changes.
set -euo pipefail
echo "STABLE_GIT_COMMIT $(git rev-parse HEAD)"
if [ -n "$(git status --porcelain)" ]; then
  echo "STABLE_GIT_DIRTY true"
else
  echo "STABLE_GIT_DIRTY false"
fi
