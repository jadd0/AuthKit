#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

COMMIT="$(git rev-parse --short HEAD)"

run_and_extract_count() {
  local script_name="$1"
  local output
  output="$(npm run "$script_name" --silent 2>&1)"
  echo "$output" >&2
  echo "$output" | sed -nE 's/^[[:space:]]*Tests[[:space:]]+([0-9]+)[[:space:]]+passed.*$/\1/p' | tail -n1
}

UNIT_COUNT="$(run_and_extract_count test:unit)"
NEGATIVE_COUNT="$(run_and_extract_count test:negative)"
CONFIG_COUNT="$(run_and_extract_count test:config)"

TOTAL_COUNT=$((UNIT_COUNT + NEGATIVE_COUNT + CONFIG_COUNT))

echo
echo "Aggregate test count at commit \`$COMMIT\`: $UNIT_COUNT unit tests, $NEGATIVE_COUNT negative/security tests, and $CONFIG_COUNT configuration/schema validation tests, all passing ($TOTAL_COUNT total)."