#!/usr/bin/env bash
# Fail if petition framing reaches anything published.
#
# The Why pages are rewritten from a design document written for a different
# audience. This gate is mechanical on purpose: prose review protects the
# first draft, a grep protects every later edit.
#
# Usage: check-docs-terms.sh [PATH...]
#   With no arguments, scans every file git tracks (via `git ls-files`), so
#   anything that ships is covered instead of whatever a hardcoded path list
#   remembered to include -- except this script and its own test file, which
#   legitimately contain the terms.
#   With arguments, scans exactly those paths (recursively for directories),
#   the same way this script has always worked; paths that do not exist are
#   skipped.
set -uo pipefail

# Run from the repo root so `git ls-files` and the excluded paths below
# resolve the same way regardless of where this script is invoked from.
if REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$REPO_ROOT" || exit 1
fi

# Leading \b only, deliberately no trailing boundary: bare terms and their
# inflections (petitions, petitioner) must match, but substrings inside an
# unrelated word (repetition, competition) must not.
TERMS='\b(EB1|petition|USCIS|adjudicator|immigration|criterion)'

# This gate's own implementation and its test suite legitimately contain the
# terms; nothing else that ships should.
EXCLUDE=(scripts/check-docs-terms.sh tests/test_docs_gate.py)

if [ "$#" -gt 0 ]; then
    CANDIDATES=("$@")
else
    CANDIDATES=()
    while IFS= read -r f; do
        skip=0
        for ex in "${EXCLUDE[@]}"; do
            [ "$f" = "$ex" ] && skip=1 && break
        done
        [ "$skip" -eq 0 ] && CANDIDATES+=("$f")
    done < <(git ls-files 2>/dev/null)
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
FILE_LIST="$(find "${TARGETS[@]}" -type f 2>/dev/null)"
if [ -z "$FILE_LIST" ]; then
    FILE_COUNT=0
else
    FILE_COUNT="$(printf '%s\n' "$FILE_LIST" | wc -l | tr -d ' ')"
fi
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
CONTENT_OUT="$(mktemp)"
CONTENT_ERR="$(mktemp)"
PATH_OUT="$(mktemp)"
PATH_ERR="$(mktemp)"
trap 'rm -f "$CONTENT_OUT" "$CONTENT_ERR" "$PATH_OUT" "$PATH_ERR"' EXIT

grep -rniE "$TERMS" "${TARGETS[@]}" >"$CONTENT_OUT" 2>"$CONTENT_ERR"
CONTENT_STATUS=$?

# A page's filename becomes its published URL slug, so the path itself must
# be checked against the terms too, not just what's inside the file.
printf '%s\n' "$FILE_LIST" | grep -niE "$TERMS" >"$PATH_OUT" 2>"$PATH_ERR"
PATH_STATUS=$?

if [ "$CONTENT_STATUS" -gt 1 ] || [ "$PATH_STATUS" -gt 1 ]; then
    cat "$CONTENT_ERR" "$PATH_ERR" >&2
    echo "check-docs-terms: scan could not be completed (grep exit $CONTENT_STATUS/$PATH_STATUS)" >&2
    exit 1
fi

if [ "$CONTENT_STATUS" -eq 0 ] || [ "$PATH_STATUS" -eq 0 ]; then
    if [ "$CONTENT_STATUS" -eq 0 ]; then
        cat "$CONTENT_OUT"
    fi
    if [ "$PATH_STATUS" -eq 0 ]; then
        echo "Matched in a file path (which becomes the published URL slug):"
        sed 's/^/  /' "$PATH_OUT"
    fi
    echo "" >&2
    echo "check-docs-terms: the terms above must not appear in published" >&2
    echo "documentation. Rewrite the wording rather than deleting the page." >&2
    exit 1
fi

echo "check-docs-terms: clean (${#TARGETS[@]} paths, ${FILE_COUNT} files)"
exit 0
