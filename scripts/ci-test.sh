#!/usr/bin/env bash
# Run `cargo test` in CI and surface every failing test as a GitHub Actions error
# annotation, so the failure is readable on the run page without opening the log.
#
#   scripts/ci-test.sh <cargo test args...>
#
# `--no-fail-fast` keeps going after the first failing crate so one run reports all of
# them. Exit status is cargo's.
set -uo pipefail
cd "$(dirname "$0")/.."

log=$(mktemp)
cargo test --no-fail-fast "$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}

if [ "$status" -ne 0 ]; then
  # "test foo::bar ... FAILED" lines name the tests; "panicked at <file>:<line>:<col>:"
  # lines give the location. Doc-test and compile errors are reported from "error" lines.
  grep -E '^test .* FAILED$' "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/::error title=test failed::\1/' | sort -u
  grep -E "panicked at [^:]+:[0-9]+:[0-9]+:" "$log" \
    | sed -E "s/^thread '([^']*)'.*panicked at ([^:]+):([0-9]+):[0-9]+:.*/::error file=\2,line=\3,title=panic in \1::\1/" | sort -u | head -50
  grep -E '^(error(\[E[0-9]+\])?:|error: test failed)' "$log" | sed -E 's/^/::error::/' | sort -u | head -20
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
      echo "### Failing tests"
      grep -E '^test .* FAILED$' "$log" | sed -E 's/^test (.*) \.\.\. FAILED$/- `\1`/' | sort -u
      echo
      echo '```'
      grep -E -A12 '^---- .* stdout ----$' "$log" | head -200
      echo '```'
    } >> "$GITHUB_STEP_SUMMARY"
  fi
fi
rm -f "$log"
exit "$status"
