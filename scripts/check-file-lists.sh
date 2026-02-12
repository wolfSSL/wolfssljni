#!/bin/bash
#
# Checks that manually-maintained file lists across build/project files stay
# in sync with the actual source files on disk.
#
# Checked lists:
#   Java files  : scripts/infer.sh
#   Native .c   : IDE/WIN/wolfssljni.vcxproj
#                  IDE/WIN/wolfssljni.vcxproj.filters
#                  IDE/Android/app/src/main/cpp/CMakeLists.txt
#                  platform/android_aosp/wolfssljni/Android.mk
#   Native .h   : IDE/WIN/wolfssljni.vcxproj
#                  IDE/WIN/wolfssljni.vcxproj.filters
#
# Run from wolfssljni root:
#   ./scripts/check-file-lists.sh
#
# Returns 0 if all lists match, 1 if any mismatch is found.

# cd to repo root (parent of scripts/)
cd "$(dirname "$0")/.." || exit 1

FAIL=0

# ---------------------- helper functions ----------------------

# Print a sorted, newline-delimited list to stdout.  Arguments are the items.
sort_list() {
    printf '%s\n' "$@" | sort
}

# Compare two sorted lists (passed as strings with newline separators).
# $1 = label for first list
# $2 = first list (newline-separated)
# $3 = label for second list
# $4 = second list (newline-separated)
compare_lists() {
    local label_a="$1" list_a="$2" label_b="$3" list_b="$4"
    local only_a only_b

    only_a=$(comm -23 <(echo "$list_a") <(echo "$list_b"))
    only_b=$(comm -13 <(echo "$list_a") <(echo "$list_b"))

    if [ -n "$only_a" ] || [ -n "$only_b" ]; then
        echo "MISMATCH between $label_a and $label_b"
        if [ -n "$only_a" ]; then
            echo "  In $label_a but not $label_b:"
            echo "$only_a" | sed 's/^/    /'
        fi
        if [ -n "$only_b" ]; then
            echo "  In $label_b but not $label_a:"
            echo "$only_b" | sed 's/^/    /'
        fi
        echo
        FAIL=1
    fi
}

# ---------------------- collect actual files on disk ----------------------

# Java source files (non-test), paths relative to repo root
DISK_JAVA=$(find src/java -name '*.java' -not -path '*/test/*' | sort)

# Native .c files – basenames only (each manifest uses different path prefixes)
DISK_C=$(find native -maxdepth 1 -name '*.c' -printf '%f\n' | sort)

# Native .h files – basenames only
DISK_H=$(find native -maxdepth 1 -name '*.h' -printf '%f\n' | sort)

# ======================== Java source checks ========================

echo "Checking Java source files in scripts/infer.sh..."

# --- scripts/infer.sh ---
INFER_JAVA=$(grep '\.java' scripts/infer.sh \
    | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*\\$//' \
    | sort)

compare_lists "disk (src/java)" "$DISK_JAVA" \
              "scripts/infer.sh" "$INFER_JAVA"

# ======================== Native .c checks ========================

# --- IDE/WIN/wolfssljni.vcxproj ---
echo "Checking native .c files in IDE/WIN/wolfssljni.vcxproj..."
VCXPROJ_C=$(grep '<ClCompile Include=' IDE/WIN/wolfssljni.vcxproj \
    | sed 's/.*Include="[^"]*\\\([^"\\]*\)".*/\1/' \
    | sort)

compare_lists "disk (native/*.c)" "$DISK_C" \
              "IDE/WIN/wolfssljni.vcxproj <ClCompile>" "$VCXPROJ_C"

# --- IDE/WIN/wolfssljni.vcxproj.filters ---
echo "Checking native .c files in IDE/WIN/wolfssljni.vcxproj.filters..."
FILTERS_C=$(grep '<ClCompile Include=' IDE/WIN/wolfssljni.vcxproj.filters \
    | sed 's/.*Include="[^"]*\\\([^"\\]*\)".*/\1/' \
    | sort)

compare_lists "IDE/WIN/wolfssljni.vcxproj <ClCompile>" "$VCXPROJ_C" \
              "IDE/WIN/wolfssljni.vcxproj.filters <ClCompile>" "$FILTERS_C"

# --- IDE/Android/app/src/main/cpp/CMakeLists.txt ---
# Extract files from the add_library(wolfssljni SHARED ...) block
CMAKE=IDE/Android/app/src/main/cpp/CMakeLists.txt
echo "Checking native .c files in $CMAKE..."
CMAKE_C=$(sed -n '/^add_library(wolfssljni SHARED/,/^)/p' "$CMAKE" \
    | grep '\.c' \
    | sed 's|.*native/||; s/)//; s/^[[:space:]]*//' \
    | sort)

compare_lists "disk (native/*.c)" "$DISK_C" \
              "CMakeLists.txt add_library(wolfssljni)" "$CMAKE_C"

# --- platform/android_aosp/wolfssljni/Android.mk ---
# Extract LOCAL_SRC_FILES from the native library section (after second
# "include $(CLEAR_VARS)")
AOSP_MK=platform/android_aosp/wolfssljni/Android.mk
echo "Checking native .c files in $AOSP_MK..."
AOSP_C=$(sed -n '/^# Create wolfSSL JNI native/,/^include \$(BUILD_SHARED_LIBRARY)/p' "$AOSP_MK" \
    | grep '\.c' \
    | sed 's|.*native/||; s/[[:space:]]*\\$//' \
    | sed 's/^[[:space:]]*//' \
    | sort)

compare_lists "disk (native/*.c)" "$DISK_C" \
              "platform/android_aosp/wolfssljni/Android.mk native" "$AOSP_C"

# ======================== Native .h checks ========================

# --- IDE/WIN/wolfssljni.vcxproj ---
echo "Checking native .h files in IDE/WIN/wolfssljni.vcxproj..."
VCXPROJ_H=$(grep '<ClInclude Include=' IDE/WIN/wolfssljni.vcxproj \
    | sed 's/.*Include="[^"]*\\\([^"\\]*\)".*/\1/' \
    | sort)

compare_lists "disk (native/*.h)" "$DISK_H" \
              "IDE/WIN/wolfssljni.vcxproj <ClInclude>" "$VCXPROJ_H"

# --- IDE/WIN/wolfssljni.vcxproj.filters ---
echo "Checking native .h files in IDE/WIN/wolfssljni.vcxproj.filters..."
FILTERS_H=$(grep '<ClInclude Include=' IDE/WIN/wolfssljni.vcxproj.filters \
    | sed 's/.*Include="[^"]*\\\([^"\\]*\)".*/\1/' \
    | sort)

compare_lists "IDE/WIN/wolfssljni.vcxproj <ClInclude>" "$VCXPROJ_H" \
              "IDE/WIN/wolfssljni.vcxproj.filters <ClInclude>" "$FILTERS_H"

# ======================== Summary ========================

if [ "$FAIL" -eq 0 ]; then
    echo "All file lists are in sync."
    exit 0
else
    echo "File list mismatches detected (see above)."
    exit 1
fi
