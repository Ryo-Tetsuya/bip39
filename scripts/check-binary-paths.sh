#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -eq 0 ]]; then
  echo "Usage: scripts/check-binary-paths.sh <binary> [binary...]" >&2
  exit 2
fi

pattern='(/Users/|/home/|/root/|C:\\Users\\|C:/Users/|/private/var|/var/folders|/private/tmp|Documents/Git)'
failed=0
leak_file="$(mktemp -t bip39-path-leaks.XXXXXX)"
trap 'rm -f "$leak_file"' EXIT

for binary_path in "$@"; do
  if [[ ! -f "$binary_path" ]]; then
    echo "Binary not found: $binary_path" >&2
    failed=1
    continue
  fi

  if LC_ALL=C strings "$binary_path" | grep -E -i "$pattern" >"$leak_file"; then
    echo "Path leak found in $binary_path:" >&2
    head -20 "$leak_file" >&2
    failed=1
  else
    echo "No local path leaks found in $binary_path"
  fi
done

exit "$failed"
