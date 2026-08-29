#!/usr/bin/env bash
# Compute (or verify) the content identity of the immutable KNOT core.
#
# The core is exactly the header set under include/ccts/. Its identity is the
# SHA-256 of each file plus a combined "tree digest" (SHA-256 over the sorted
# "<sha256>  <path>" lines). The recorded values live in
# metadata/core-digests.sha256 and are what every evidence record refers to.
#
#   scripts/core_digest.sh            print the per-file digests and the tree digest
#   scripts/core_digest.sh --check    verify the working tree matches the recorded digests
#   scripts/core_digest.sh --tree     print only the tree digest
#   scripts/core_digest.sh --update   rewrite metadata/core-digests.sha256 (deliberate core change only)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
RECORD="metadata/core-digests.sha256"
CORE_GLOB="include/ccts/*.hpp"

compute() {
    # shellcheck disable=SC2086
    LC_ALL=C sha256sum $CORE_GLOB | LC_ALL=C sort -k2
}
tree_digest() {
    compute | sha256sum | cut -d' ' -f1
}

case "${1:-}" in
    --tree) tree_digest ;;
    --update)
        { echo "# KNOT core identity: SHA-256 of every file in include/ccts/ (not modified by the"
          echo "# assurance layer). Verify with: scripts/core_digest.sh --check"
          echo "# Regenerate ONLY for a deliberate, reviewed core change: scripts/core_digest.sh --update"
          compute
          echo "# tree-digest $(tree_digest)"; } > "$RECORD"
        echo "wrote $RECORD" ;;
    --check)
        [ -f "$RECORD" ] || { echo "core_digest: $RECORD missing" >&2; exit 2; }
        expected="$(grep -v '^#' "$RECORD")"
        actual="$(compute)"
        if [ "$expected" != "$actual" ]; then
            echo "core_digest: KNOT core differs from the recorded identity" >&2
            diff <(echo "$expected") <(echo "$actual") >&2 || true
            exit 1
        fi
        rec_tree="$(grep '^# tree-digest' "$RECORD" | awk '{print $3}')"
        act_tree="$(tree_digest)"
        [ "$rec_tree" = "$act_tree" ] || { echo "core_digest: tree digest mismatch" >&2; exit 1; }
        echo "core_digest: OK (tree $act_tree)" ;;
    "") compute; echo "tree-digest $(tree_digest)" ;;
    *) echo "usage: $0 [--check|--tree|--update]" >&2; exit 2 ;;
esac
