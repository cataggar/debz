#!/usr/bin/env bash
# Precompiler checks: this file must itself be checked before it is sourced.
reference_protected_path() {
  local path=$1 kind=$2 current=/ rest=${1#/} part metadata last=false
  [[ "$path" == /* && "$kind" =~ ^(file|directory)$ ]] || return 2
  while :; do
    [[ ! -L "$current" ]] || {
      echo "non-root or writable reference path: $current (symbolic link)" >&2
      return 2
    }
    metadata=$(stat -c '%u:%g:%a' -- "$current") || return
    [[ "$metadata" =~ ^0:0:[0-7]{3,4}$ ]] && (( (8#${metadata##*:} & 022) == 0 )) || {
      echo "non-root or writable reference path: $current (writable or non-root ancestor)" >&2
      return 2
    }
    if [[ -z "$rest" ]]; then
      if [[ "$kind" == directory ]]; then [[ -d "$current" ]]; else [[ -f "$current" ]]; fi
      return "$?"
    fi
    [[ -d "$current" ]] || return 2
    part=${rest%%/*}
    [[ -n "$part" && "$part" != . && "$part" != .. ]] || return 2
    current="${current%/}/$part"
    if [[ "$rest" == "$part" ]]; then rest=; else rest=${rest#*/}; [[ -n "$rest" ]] || return 2; fi
  done
}

reference_toolchain() (
  set -euo pipefail
  local compiler=$1 library entry target kind owner group mode
  [[ "$compiler" == /* ]] || {
    echo "an explicit absolute protected DEBZ_ZIG compiler is required" >&2
    return 2
  }
  reference_protected_path "$compiler" file
  [[ -x "$compiler" ]] || return 2
  library=$(dirname -- "$compiler")/lib
  reference_protected_path "$library" directory
  find -P "$library" -printf '%y:%U:%G:%m:%p\0' |
  while IFS=: read -r -d '' kind owner group mode entry; do
    if [[ "$kind" == l ]]; then
      target=$(realpath -e -- "$entry")
      [[ "$target" == "$library" || "$target" == "$library"/* ]] || {
        echo "toolchain library symlink escapes: $entry" >&2
        return 2
      }
      kind=file
      [[ ! -d "$target" ]] || kind=directory
      reference_protected_path "$target" "$kind"
    else
      [[ "$kind" == f || "$kind" == d ]] && [[ "$owner:$group" == 0:0 && "$mode" =~ ^[0-7]{3,4}$ ]] &&
        (( (8#$mode & 022) == 0 )) || {
          echo "non-root or writable reference path: $entry (writable or non-root library member)" >&2
          return 2
        }
    fi
  done
  printf '%s\n' "$library"
)
