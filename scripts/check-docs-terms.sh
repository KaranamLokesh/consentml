#!/usr/bin/env bash
# Fail if petition framing reaches anything published.
#
# The Why pages are rewritten from a design document written for a different
# audience. This gate is mechanical on purpose: prose review protects the
# first draft, a grep protects every later edit.
#
# Usage: check-docs-terms.sh [PATH...]
#   With no arguments, scans the published set. Paths that do not exist are
#   skipped, so this works before CONTRIBUTING.md is added.
set -uo pipefail

# Leading \b only, deliberately no trailing boundary: bare terms and their
# inflections (petitions, petitioner) must match, but substrings inside an
# unrelated word (repetition, competition) must not.
TERMS='\b(EB1|petition|USCIS|adjudicator|immigration|criterion)'

if [ "$#" -gt 0 ]; then
    CANDIDATES=("$@")
else
    CANDIDATES=(docs-site mkdocs.yml README.md CONTRIBUTING.md)
fi

TARGETS=()
for path in "${CANDIDATES[@]}"; do
    [ -e "$path" ] && TARGETS+=("$path")
done

if [ "${#TARGETS[@]}" -eq 0 ]; then
    # Never pass by default. If the paths moved, the gate is broken, and a
    # broken gate that exits 0 is worse than no gate.
    echo "check-docs-terms: nothing to scan; the paths moved or are wrong" >&2
    exit 1
fi

# Guard on files that will actually be read, not just on path existence: an
# existing-but-emptied directory (bad rename, failed build step) must not
# read as "clean" merely because the directory itself is still there. If the
# count can't even be determined, fail closed rather than guess.
FILE_COUNT="$(find "${TARGETS[@]}" -type f 2>/dev/null | wc -l | tr -d ' ')"
if [ -z "$FILE_COUNT" ] || [ "$FILE_COUNT" -eq 0 ]; then
    echo "check-docs-terms: nothing to scan; no readable files under ${TARGETS[*]}" >&2
    exit 1
fi

# Capture stdout and stderr separately so a "permission denied" line on
# stderr is never mistaken for a matched line on stdout, and branch on the
# real exit status instead of a truthiness check: grep exits 0 (matches), 1
# (no matches), or >1 (grep itself failed, e.g. an unreadable subdirectory).
# Treating anything other than 0 as "clean" is the bug this replaces -- a
# scan grep couldn't complete must never be reported as passing.
GREP_OUT="$(mktemp)"
GREP_ERR="$(mktemp)"
trap 'rm -f "$GREP_OUT" "$GREP_ERR"' EXIT

grep -rniE "$TERMS" "${TARGETS[@]}" >"$GREP_OUT" 2>"$GREP_ERR"
STATUS=$?

case "$STATUS" in
    0)
        cat "$GREP_OUT"
        echo "" >&2
        echo "check-docs-terms: the terms above must not appear in published" >&2
        echo "documentation. Rewrite the wording rather than deleting the page." >&2
        exit 1
        ;;
    1)
        echo "check-docs-terms: clean (${TARGETS[*]})"
        exit 0
        ;;
    *)
        cat "$GREP_ERR" >&2
        echo "check-docs-terms: scan could not be completed (grep exit $STATUS)" >&2
        exit 1
        ;;
esac
