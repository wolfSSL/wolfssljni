#!/usr/bin/env bash
#
# Check for >80-char lines introduced by the current diff, ignoring existing
# long lines.
#
# To run automatically, create one of these files:
# .git/hooks/pre-commit (local checks before commit)
# .git/hooks/pre-push (checks before pushing to remote)
# 
# Example hook file content:
# #!/usr/bin/env bash
# set -euo pipefail
# if [[ -z "${BASE_REF:-}" ]]; then
#   BASE_REF="master"
# fi
# if [[ -f "scripts/line-length-check-added-lines.sh" ]]; then
#   scripts/line-length-check-added-lines.sh "$BASE_REF"
# else
#   echo "line-length-check-added-lines.sh not found, skipping line length check"
# fi

set -euo pipefail

BASE_INPUT="${1:-${BASE_REF:-}}"
if [[ -z "$BASE_INPUT" ]]; then
  echo "Usage: $0 <base-ref>" >&2
  echo "Or set BASE_REF in the environment." >&2
  exit 2
fi
BASE_REF="$BASE_INPUT"

echo "Checking line length (max 80 characters) against base ref: $BASE_REF"

all_files="$(mktemp -t all_files.XXXXXX)"
long_lines="$(mktemp -t long_lines.XXXXXX)"
violations_file="$(mktemp -t violations_file.XXXXXX)"

cleanup() {
  rm -f "$all_files" "$long_lines" "$violations_file" "${added_lines_file:-}"
}
trap cleanup EXIT

# Scan long lines across repo (tracked files), then filter to the diff.
# Limit to src/, examples/, and native/ directories.
git ls-files -- src examples native > "$all_files"

violation_count=0

while IFS= read -r file; do
  if [[ -f "$file" ]]; then
    if [[ "$file" == \
      "src/java/com/wolfssl/provider/jsse/WolfSSLProvider.java" ]]; then
      continue
    fi

    if [[ "$file" =~ \.(pem|crt|cer|der|key)$ ]]; then
      continue
    fi

    if [[ "$file" =~ \.sh$ ]]; then
      continue
    fi

    if ! LC_ALL=C grep -Iq . "$file"; then
      continue
    fi

    LC_ALL=C awk -v file="$file" \
      'length($0) > 80 { print file ":" FNR ":" $0 }' "$file" \
      >> "$long_lines"
  fi
done < "$all_files"

while IFS= read -r entry; do
  file="${entry%%:*}"
  rest="${entry#*:}"
  line_num="${rest%%:*}"
  line_text="${rest#*:}"

  if [[ "$file" != "${last_file:-}" ]]; then
    rm -f "${added_lines_file:-}"
    added_lines_file="$(mktemp -t added_lines_file.XXXXXX)"
    git diff -U0 "$BASE_REF"...HEAD -- "$file" | \
      awk '
        /^@@/ {
          if (match($0, /\+[0-9]+/)) {
            n = substr($0, RSTART + 1, RLENGTH - 1)
          }
          next
        }
        /^\+/ && !/^\+\+\+/ {
          print n
          n++
        }
      ' > "$added_lines_file"
    last_file="$file"
  fi

  if grep -qx "$line_num" "$added_lines_file"; then
    jni_skip=0
    if [[ "$line_text" =~ JNIEXPORT.*JNICALL.*Java_com_wolfssl_ ]]; then
      jni_skip=1
    elif [[ "$line_text" =~ Java_com_wolfssl_.*\( ]]; then
      jni_skip=1
    elif [[ "$line_text" =~ \
      ^[[:space:]]*return[[:space:]]+Java_com_wolfssl_.* ]]; then
      jni_skip=1
    elif [[ "$line_text" =~ \
      ^[[:space:]]*\(JNIEnv\*[[:space:]]+env.*\) ]]; then
      jni_skip=1
    elif [[ "$line_text" =~ ^[[:space:]]*JNIEnv\*[[:space:]]+env.* ]]; then
      jni_skip=1
    fi

    if [[ $jni_skip -eq 1 ]]; then
      if [[ "${VERBOSE:-0}" == "1" ]]; then
        printf " %s:%s - Skipping JNI line (%d chars)\n" \
          "$file" "$line_num" "${#line_text}"
        echo "   Line: $line_text"
      fi
    else
      printf " %s:%s - Line too long (%d chars)\n" \
        "$file" "$line_num" "${#line_text}"
      echo "   Line: $line_text"
      echo "violation" >> "$violations_file"
    fi
  fi
done < "$long_lines"

if [[ -f "$violations_file" ]]; then
  violation_count=$(grep -c "violation" "$violations_file" || true)
  violation_count=${violation_count:-0}
else
  violation_count=0
fi

if [[ $violation_count -gt 0 ]]; then
  echo " Found $violation_count line(s) exceeding 80 chars in PR changes"
  echo ""
  echo "Please ensure all lines are 80 characters or less."
  echo "Check line length in your editor or use:"
  echo "  grep -n '.\{81,\}' <filename>"
  exit 1
else
  echo "All changed lines are within the 80 character limit"
  exit 0
fi
