#!/usr/bin/env bash
# Cursor afterFileEdit hook: warn when a Python file exceeds 200 lines.
# Reads JSON from stdin with { "file_path": "..." }
# Outputs JSON to stdout. Exit 0 = allow (with optional warning).

set -euo pipefail

MAX_LINES=200

# Read hook input from stdin
INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('file_path',''))" 2>/dev/null || echo "")

# Skip non-Python files
if [[ "$FILE_PATH" != *.py ]]; then
  echo '{}'
  exit 0
fi

# Skip if file doesn't exist (deleted)
if [[ ! -f "$FILE_PATH" ]]; then
  echo '{}'
  exit 0
fi

LINE_COUNT=$(wc -l < "$FILE_PATH" | tr -d ' ')

if [[ "$LINE_COUNT" -gt "$MAX_LINES" ]]; then
  FILENAME=$(basename "$FILE_PATH")
  cat <<EOF
{
  "decision": "deny",
  "reason": "⚠️ FILE SIZE LIMIT: ${FILENAME} has ${LINE_COUNT} lines (max ${MAX_LINES}). Split it into a subfolder module per .cursor/rules/file-size-limits.mdc — convert the file into a package directory with __init__.py re-exporting the public API."
}
EOF
  exit 2
fi

echo '{}'
exit 0
