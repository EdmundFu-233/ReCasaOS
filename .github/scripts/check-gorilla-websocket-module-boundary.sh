#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'Gorilla WebSocket module boundary failed: %s\n' "$*" >&2
  exit 1
}

# GO-2026-6278 currently names v1.5.3 as fixed, but that tag still generates
# client mask keys with math/rand. Official-upstream commit
# d67f41855da42d7bccd9ef050c49f7e54e783b95 changes the implementation to
# crypto/rand; the pseudo-version and both module checksums lock its source.
expected_path='github.com/gorilla/websocket'
expected_version='v1.5.4-0.20240701034025-d67f41855da4'
expected_sum='h1:PYKzliEgITjLJoJqbV90S0YRaG8LNAsICH6fp6MApC0='
expected_go_mod_sum='h1:r4w70xmWCQKmi1ONH4KIaBptdivuRPyosB9RmPlGEwA='
input_file=
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
[[ -f "$repository_root/go.mod" && ! -L "$repository_root/go.mod" ]] ||
  fail 'repository root go.mod is missing or linked'
[[ ! -e "$repository_root/vendor" && ! -L "$repository_root/vendor" ]] ||
  fail 'repository vendor directory or link is not allowed'
for workspace_file in go.work go.work.sum; do
  [[ ! -e "$repository_root/$workspace_file" && ! -L "$repository_root/$workspace_file" ]] ||
    fail "repository $workspace_file file or link is not allowed"
done
cd "$repository_root"

case $# in
  0) ;;
  2)
    [[ "$1" == --input ]] ||
      fail 'usage: check-gorilla-websocket-module-boundary.sh [--input FILE]'
    input_file=$2
    ;;
  *) fail 'usage: check-gorilla-websocket-module-boundary.sh [--input FILE]' ;;
esac

is_unreviewed_websocket_path() {
  local candidate=$1
  [[ "$candidate" != "$expected_path" ]] || return 1
  case "$candidate" in
    "$expected_path"/*|*/websocket|*/websocket/*) return 0 ;;
  esac
  return 1
}

load_graph() {
  if [[ -n "$input_file" ]]; then
    [[ -f "$input_file" && ! -L "$input_file" ]] ||
      fail 'fixture input must be a regular non-symlink file'
    local input_bytes
    input_bytes=$(wc -c <"$input_file" | tr -d '[:space:]')
    [[ "$input_bytes" =~ ^[0-9]+$ && "$input_bytes" -le 1048576 ]] ||
      fail 'fixture input exceeds the 1 MiB limit'
    module_graph=$(<"$input_file")
    return
  fi

  if ! module_graph=$(
    GOWORK=off GOFLAGS=-mod=readonly go list -m -f \
      '{{.Path}}|{{.Version}}|{{.Sum}}|{{.GoModSum}}{{with .Replace}}|{{.Path}}|{{.Version}}|{{.Sum}}|{{.GoModSum}}{{end}}' \
      all
  ); then
    fail 'go list could not produce the complete module graph'
  fi

  local graph_bytes
  graph_bytes=$(printf '%s' "$module_graph" | wc -c | tr -d '[:space:]')
  [[ "$graph_bytes" =~ ^[0-9]+$ && "$graph_bytes" -le 1048576 ]] ||
    fail 'module graph exceeds the 1 MiB limit'
}

module_graph=
load_graph
[[ -n "$module_graph" ]] || fail 'module graph is empty'

expected_count=0
record_count=0
while IFS='|' read -r \
  module_path module_version module_sum module_go_mod_sum \
  replace_path replace_version replace_sum replace_go_mod_sum extra
do
  [[ -n "$module_path" ]] || fail 'module graph contains an empty path'
  for field in \
    "$module_path" "$module_version" "$module_sum" "$module_go_mod_sum" \
    "${replace_path:-}" "${replace_version:-}" "${replace_sum:-}" \
    "${replace_go_mod_sum:-}"
  do
    [[ "$field" != *[[:space:]]* ]] || fail 'module record contains whitespace'
  done
  [[ -z "${extra:-}" ]] || fail "module record has extra fields: $module_path"
  if [[ -z "${replace_path:-}" ]]; then
    [[ -z "${replace_version:-}${replace_sum:-}${replace_go_mod_sum:-}" ]] ||
      fail 'replacement metadata is missing its path'
  fi

  record_count=$((record_count + 1))
  [[ "$record_count" -le 2048 ]] || fail 'module graph exceeds the record limit'

  if is_unreviewed_websocket_path "$module_path"; then
    fail "unreviewed Gorilla WebSocket module selected: $module_path"
  fi
  if [[ -n "${replace_path:-}" ]] && is_unreviewed_websocket_path "$replace_path"; then
    fail "unreviewed Gorilla WebSocket replacement selected: $replace_path"
  fi

  if [[ "$module_path" == "$expected_path" ]]; then
    [[ -z "${replace_path:-}" ]] || fail 'reviewed Gorilla WebSocket module must not be replaced'
    [[ "$module_version" == "$expected_version" ]] ||
      fail "reviewed Gorilla WebSocket module has unexpected version: $module_version"
    [[ "$module_sum" == "$expected_sum" ]] ||
      fail "reviewed Gorilla WebSocket module has unexpected zip checksum: $module_sum"
    [[ "$module_go_mod_sum" == "$expected_go_mod_sum" ]] ||
      fail "reviewed Gorilla WebSocket module has unexpected go.mod checksum: $module_go_mod_sum"
    expected_count=$((expected_count + 1))
  elif [[ -n "${replace_path:-}" && "$replace_path" == "$expected_path" ]]; then
    fail 'reviewed Gorilla WebSocket module must be selected directly, not as a replacement'
  fi
done <<<"$module_graph"

[[ "$record_count" -gt 0 ]] || fail 'module graph contains no records'
[[ "$expected_count" == 1 ]] ||
  fail "reviewed Gorilla WebSocket module count is $expected_count, want 1"

if [[ -z "$input_file" ]]; then
  if ! GOWORK=off GOFLAGS=-mod=readonly go mod download "$expected_path@$expected_version"; then
    fail 'reviewed Gorilla WebSocket module download failed'
  fi
  if ! GOWORK=off GOFLAGS=-mod=readonly go mod verify >/dev/null; then
    fail 'module cache verification failed'
  fi
fi

printf 'Gorilla WebSocket module boundary passed: %s@%s\n' \
  "$expected_path" "$expected_version"
