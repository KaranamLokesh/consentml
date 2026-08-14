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

TERMS='EB1|petition|USCIS|adjudicator|immigration|criterion'

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

if grep -rniE "$TERMS" "${TARGETS[@]}"; then
    echo "" >&2
    echo "check-docs-terms: the terms above must not appear in published" >&2
    echo "documentation. Rewrite the wording rather than deleting the page." >&2
    exit 1
fi

echo "check-docs-terms: clean (${TARGETS[*]})"
