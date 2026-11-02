#!/bin/sh
# Run the pinned gitleaks over the reachable history, the current tree and the extracted members of the current
# archives, each with its own report. Every scan runs even if an earlier one fails; the script fails if any scan
# fails, finds something, or leaves no report. See docs/CI.md (Secret scan).
#   SRC       repository checkout with full history, read-only    (default /src)
#   OUT       evidence directory, read-write                      (default /out)
#   WORK      scratch directory                                   (default /work)
#   GITLEAKS  the checksum-verified gitleaks 8.24.3 binary         (required)
#   MANIFEST  optional archive list for extract_archives.py (trial fixtures only)
set -u
SRC="${SRC:-/src}"; OUT="${OUT:-/out}"; WORK="${WORK:-/work}"
: "${GITLEAKS:?set GITLEAKS to the verified gitleaks binary}"
mkdir -p "$OUT" "$WORK"
exec > "$OUT/run.log" 2>&1
set -x
"$GITLEAKS" version
CONFIG="$SRC/.gitleaks.toml"
COMMON="--redact --no-banner --config $CONFIG --report-format json"

extract=0
if [ -n "${MANIFEST:-}" ]; then
  python3 -I "$SRC/ci/extract_archives.py" "$SRC" "$WORK/archives" --report "$OUT/archives-manifest.json" \
    --manifest "$MANIFEST" || extract=$?
else
  python3 -I "$SRC/ci/extract_archives.py" "$SRC" "$WORK/archives" --report "$OUT/archives-manifest.json" || extract=$?
fi

history=0
"$GITLEAKS" git "$SRC" --log-opts=--all $COMMON --report-path "$OUT/history.json" || history=$?
tree=0
"$GITLEAKS" dir "$SRC" $COMMON --report-path "$OUT/tree.json" || tree=$?
archives=0
if [ "$extract" -eq 0 ]; then
  (cd "$WORK/archives" && "$GITLEAKS" dir . $COMMON --report-path "$OUT/archives.json") || archives=$?
else
  archives=skipped
fi

missing=""
for report in history tree archives archives-manifest; do
  [ -s "$OUT/$report.json" ] || missing="$missing $report"
done
{
  echo "extract: $extract"
  echo "history: $history"
  echo "tree: $tree"
  echo "archives: $archives"
  echo "missing reports:${missing:- none}"
} > "$OUT/scan-status.txt"
cat "$OUT/scan-status.txt"
[ "$extract" = 0 ] && [ "$history" = 0 ] && [ "$tree" = 0 ] && [ "$archives" = 0 ] && [ -z "$missing" ]
