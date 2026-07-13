#!/usr/bin/env bash
# Fast, dependency-free frontend verification.
#
#  1. Syntax-checks every split module independently (node --check). Because the
#     browser loads each public/js/*.js as a SEPARATE <script>, each must parse
#     on its own — this catches any boundary that cut through a function.
#  2. Confirms index.html references every module in public/js/ (and vice versa),
#     so nothing is orphaned or missing from the load order.
#
# For the full runtime smoke test see test/frontend-smoke.mjs.
set -euo pipefail
cd "$(dirname "$0")/.."

JS_DIR="public/js"
HTML="public/index.html"
fail=0

echo "== 1. Per-file syntax check =="
for f in "$JS_DIR"/*.js; do
  if node --check "$f" 2>/tmp/nc_err; then
    printf "  ok   %s\n" "$f"
  else
    fail=1
    printf "  FAIL %s\n" "$f"
    sed 's/^/       /' /tmp/nc_err
  fi
done

echo ""
echo "== 2. index.html references match public/js/ =="
for f in "$JS_DIR"/*.js; do
  base="$(basename "$f")"
  if ! grep -q "/js/$base" "$HTML"; then
    fail=1
    printf "  MISSING from index.html: %s\n" "$base"
  fi
done
# every /js/*.js referenced in index.html must exist on disk
while IFS= read -r ref; do
  [ -f "public$ref" ] || { fail=1; printf "  REFERENCED but not on disk: %s\n" "$ref"; }
done < <(grep -oE '/js/[0-9A-Za-z._-]+\.js' "$HTML")

if [ "$fail" -eq 0 ]; then
  echo "  ok   index.html and public/js/ are consistent"
fi

echo ""
if [ "$fail" -eq 0 ]; then
  echo "RESULT: PASS"
else
  echo "RESULT: FAIL"
fi
exit "$fail"
