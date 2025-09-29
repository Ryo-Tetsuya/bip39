#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"

sep=$'\x1f'
encoded_flags=()

append_flag() {
  encoded_flags+=("$1")
}

append_remap() {
  local from="${1%/}"
  local to="$2"

  if [[ -n "$from" ]]; then
    append_flag "--remap-path-prefix=$from=$to"
  fi
}

append_remap_variants() {
  local from="${1%/}"
  local to="$2"

  append_remap "$from" "$to"

  if command -v cygpath >/dev/null 2>&1 && [[ -e "$from" ]]; then
    append_remap "$(cygpath -m "$from")" "$to"
    append_remap "$(cygpath -w "$from")" "$to"
  fi
}

join_encoded_flags() {
  local joined=""
  local flag

  for flag in "${encoded_flags[@]}"; do
    if [[ -n "$joined" ]]; then
      joined+="$sep"
    fi
    joined+="$flag"
  done

  printf '%s' "$joined"
}

home_dir="${HOME:-}"
cargo_home="${CARGO_HOME:-}"
rustup_home="${RUSTUP_HOME:-}"
tmp_dir="${TMPDIR:-}"

if [[ -z "$cargo_home" && -n "$home_dir" ]]; then
  cargo_home="$home_dir/.cargo"
fi

if [[ -z "$rustup_home" && -n "$home_dir" ]]; then
  rustup_home="$home_dir/.rustup"
fi

# Broad remaps go first; more specific remaps follow so they win.
append_remap_variants "$home_dir" "/src"
append_remap_variants "/private/var" "/var"
append_remap_variants "/private/tmp" "/tmp"
append_remap_variants "$tmp_dir" "/tmp"
append_remap_variants "$repo_root" "/workspace"
append_remap_variants "$cargo_home" "/cargo"
append_remap_variants "$rustup_home" "/rustup"
append_flag "--remap-path-scope=all"

new_flags="$(join_encoded_flags)"
existing_flags="${CARGO_ENCODED_RUSTFLAGS:-}"

if [[ -n "$existing_flags" ]]; then
  export CARGO_ENCODED_RUSTFLAGS="$existing_flags$sep$new_flags"
else
  export CARGO_ENCODED_RUSTFLAGS="$new_flags"
fi

exec cargo "$@"
