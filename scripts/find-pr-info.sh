#!/usr/bin/env bash

# Given a PR number, print the originating fork (repo full_name) and branch.
# Default repo is wolfSSL/wolfssl. Override with --repo owner/name.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/find-pr-info.sh <pr_number> [--repo owner/name]

Outputs:
  pr:<pr_number>
  repo:<fork_full_name>
  branch:<branch_name>
  commit:<head_sha>
  status:<open|closed|merged|unknown>

Example:
  scripts/find-pr-info.sh 9631
  scripts/find-pr-info.sh 9631 --repo wolfSSL/wolfssl
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi

if [ -z "${1:-}" ]; then
  usage
  exit 2
fi

pr_number="$1"
if ! [[ "$pr_number" =~ ^[0-9]+$ ]]; then
  echo "error: PR number must be numeric" >&2
  exit 2
fi
shift

repo="wolfSSL/wolfssl"
if [ "${1:-}" = "--repo" ]; then
  if [ -z "${2:-}" ]; then
    echo "error: --repo requires owner/name" >&2
    exit 2
  fi
  repo="$2"
  shift 2
fi

if [ -n "${1:-}" ]; then
  echo "error: unexpected argument: $1" >&2
  exit 2
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not installed" >&2
  exit 127
fi

# Use GITHUB_TOKEN if set to avoid rate-limiting (60 requests/hour per IP)
auth_header=()
if [ -n "${GITHUB_TOKEN:-}" ]; then
  auth_header=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi

if ! pr_json="$(curl -fsSL "${auth_header[@]}" "https://api.github.com/repos/${repo}/pulls/${pr_number}")"; then
  curl_rc=$?
  echo "error: curl failed ($curl_rc) fetching PR #${pr_number} from ${repo}" >&2
  exit 1
fi

head_repo="$(printf "%s" "$pr_json" | jq -r '.head.repo.full_name // empty')"
head_ref="$(printf "%s" "$pr_json" | jq -r '.head.ref // empty')"
head_sha="$(printf "%s" "$pr_json" | jq -r '.head.sha // empty')"
state="$(printf "%s" "$pr_json" | jq -r '.state // empty')"
merged_at="$(printf "%s" "$pr_json" | jq -r '.merged_at // empty')"

if [ -z "$head_ref" ] || [ -z "$head_sha" ]; then
  echo "error: PR #${pr_number} missing head ref data" >&2
  exit 1
fi

# head_repo may be empty if the fork was deleted
if [ -z "$head_repo" ]; then
  head_repo="unknown"
fi

status="$state"
if [ -n "$merged_at" ]; then
  status="merged"
fi

if [ -z "$status" ]; then
  status="unknown"
fi

cat <<EOF
pr:${pr_number}
repo:${head_repo}
branch:${head_ref}
commit:${head_sha}
status:${status}
EOF
