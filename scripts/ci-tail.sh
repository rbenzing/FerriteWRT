#!/usr/bin/env bash
# ci-tail.sh <log> <label>: called when a long CI step fails. Writes the last part of
# the step's log to the GitHub job summary and turns its last error-looking lines into
# error annotations, both visible on the run page without opening the raw log. Exits 1.
set -u
log=$1 label=${2:-step}

if [ -n "${GITHUB_STEP_SUMMARY:-}" ] && [ -f "$log" ]; then
  {
    echo "### $label failed; last 150 lines"
    echo '```'
    tail -n 150 "$log" | cut -c1-400
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi
if [ -f "$log" ]; then
  grep -nE 'ERROR|error:|Error |fatal:|No such file|Permission denied|not found|failed' "$log" \
    | tail -n 8 | cut -c1-300 | sed 's/^\([0-9]*\):/::error title='"$label"' log line \1::/'
  echo "::error::$label failed; last line: $(tail -n 1 "$log" | cut -c1-300)"
fi
exit 1
