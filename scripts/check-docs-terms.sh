#!/usr/bin/env bash
# Fail if any project-specific forbidden term reaches anything published.
#
# The term list is supplied out-of-band, never committed: this repo is public,
# so the words themselves must not live in it. Provide them either as
#   CONSENTML_DOCS_TERMS='alpha|beta|gamma'   (a regex alternation body)
# or in a git-ignored file at the repo root, one term per line:
#   .docs-forbidden-terms
# CI supplies CONSENTML_DOCS_TERMS from a repository secret; a maintainer's
# local checkout uses the git-ignored file. With no list configured the scan
# is skipped (exit 0) -- there is nothing project-specific to enforce, and a
# contributor without the list has nothing to leak. The publish workflows
# require the secret separately, so the deploy path never skips silently.
#
# Usage: check-docs-terms.sh [PATH...]
#   With no arguments, scans every file git tracks (via `git ls-files`).
#   With arguments, scans exactly those paths (recursively for directories);
#   paths that do not exist are skipped.
set -uo pipefail

# Run from the repo root so `git ls-files` and the term-file path resolve the
# same way regardless of where this script is invoked from.
if REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    cd "$REPO_ROOT" || exit 1
fi

# Resolve the term list: environment first, then the git-ignored file.
TERM_FILE="${CONSENTML_DOCS_TERMS_FILE:-.docs-forbidden-terms}"
TERMS_BODY="${CONSENTML_DOCS_TERMS:-}"
if [ -z "$TERMS_BODY" ] && [ -f "$TERM_FILE" ]; then
    # One term per line; blank lines and #-comments ignored; joined with '|'.
    TERMS_BODY="$(grep -vE '^[[:space:]]*(#|$)' "$TERM_FILE" | paste -sd '|' -)"
fi

if [ -z "$TERMS_BODY" ]; then
    echo "check-docs-terms: no forbidden-term list configured; skipping" \
         "(set CONSENTML_DOCS_TERMS or create $TERM_FILE)"
    exit 0
fi

# Leading \b only, deliberately no trailing boundary: bare terms and their
# inflections (plurals, agent nouns) must match, but a term appearing as a
# substring inside an unrelated word must not.
TERMS="\b(${TERMS_BODY})"

if [ "$#" -gt 0 ]; then
    CANDIDATES=("$@")
else
    CANDIDATES=()
    while IFS= read -r f; do
        CANDIDATES+=("$f")
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
