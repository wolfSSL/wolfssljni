#!/bin/bash

# Comment Style Check Script
# Checks that .java, .c, and .h files use multi-line comments (/* */)
# instead of single-line comments (//).
#
# Usage:
#   comment-style-check.sh <base_ref>
#
# Arguments:
#   base_ref - The base branch to diff against (e.g., "main")

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "Usage: $0 <base_ref>"
    exit 1
fi

BASE_REF="$1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CHANGED_FILES="$(mktemp -t changed_files.XXXXXX)"
trap 'rm -f "$CHANGED_FILES"' EXIT

cd "$REPO_ROOT"

# Get list of changed .java and .c/.h files
DIFF_OUTPUT="$(git diff --name-only --diff-filter=AM "origin/${BASE_REF}...HEAD")"
printf '%s\n' "$DIFF_OUTPUT" | grep -E '\.(java|c|h)$' > "$CHANGED_FILES" || true

if [ ! -s "$CHANGED_FILES" ]; then
    echo "✅ Comment style check skipped - no .java, .c, or .h files were changed in this PR"
    exit 0
fi

echo "Found changed files:"
cat "$CHANGED_FILES"

violations_found=false

while IFS= read -r file; do
    if [ -f "$file" ]; then
        echo "Checking $file for comment style violations..."

        # Find potential single-line comments (//)
        # This is a simple check that may have some false positives
        # but catches the most common violations
        violations=$(grep -n '//' "$file" | \
            grep -v 'http://' | \
            grep -v 'https://' | \
            grep -v -E '/\*.*//.*\*/' | \
            grep -v -E '"[^"]*//[^"]*"' || true)

        if [ -n "$violations" ]; then
            echo "❌ Single-line comments found in $file:"
            echo "$violations"
            echo ""
            violations_found=true
        else
            echo "✅ $file: No single-line comment violations found"
        fi
    fi
done < "$CHANGED_FILES"

if [ "$violations_found" = true ]; then
    echo ""
    echo "=================================="
    echo "❌ COMMENT STYLE CHECK FAILED"
    echo "=================================="
    echo ""
    echo "Single-line comments (//) were found in the changed files."
    echo "According to the coding standard in CLAUDE.md:"
    echo "- MUST only use multi-line comments, no \"//\" style ones"
    echo ""
    echo "Please replace all single-line comments (//) with multi-line comments (/* */)."
    echo ""
    echo "Examples:"
    echo "  ❌ Bad:  // This is a comment"
    echo "  ✅ Good: /* This is a comment */"
    echo ""
    echo "  ❌ Bad:  // TODO: implement this"
    echo "  ✅ Good: /* TODO: implement this */"
    echo ""
    exit 1
else
    echo ""
    echo "=================================="
    echo "✅ COMMENT STYLE CHECK PASSED"
    echo "=================================="
    echo "All changed files follow the multi-line comment style standard."
fi
