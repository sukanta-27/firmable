#!/usr/bin/env bash
# Formats and lints each Python file an agent writes. Lint errors ruff cannot fix
# are sent back to the agent (exit 2) so it repairs them before moving on.
f=$(jq -r '.tool_input.file_path // empty')
case "$f" in
  *.py) ;;
  *) exit 0 ;;
esac
case "$f" in
  "$CLAUDE_PROJECT_DIR"/archive/*) exit 0 ;;
  "$CLAUDE_PROJECT_DIR"/*) ;;
  *) exit 0 ;;
esac

cd "$CLAUDE_PROJECT_DIR" || exit 0
uv run --quiet ruff check --fix --quiet "$f" >/dev/null 2>&1
uv run --quiet ruff format --quiet "$f"
if ! out=$(uv run --quiet ruff check --quiet "$f" 2>&1); then
  echo "$out" >&2
  exit 2
fi
