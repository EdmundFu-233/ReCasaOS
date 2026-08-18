#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'SMB2 module boundary failed: %s\n' "$*" >&2
  exit 1
}

expected_path='github.com/EdmundFu-233/go-smb2'
expected_version='v1.1.1-recasaos.1'
input_file=
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repository_root=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
[[ -f "$repository_root/go.mod" && ! -L "$repository_root/go.mod" ]] ||
  fail 'repository root go.mod is missing or linked'
cd "$repository_root"

case $# in
  0) ;;
  2)
    [[ "$1" == --input ]] || fail 'usage: check-smb2-module-boundary.sh [--input FILE]'
    input_file=$2
    ;;
  *) fail 'usage: check-smb2-module-boundary.sh [--input FILE]' ;;
esac

is_forbidden_path() {
  local candidate=$1
  local forbidden
  for forbidden in \
    github.com/hirochachacha/go-smb2 \
    github.com/CloudSoda/go-smb2 \
    github.com/cloudsoda/go-smb2 \
    github.com/CloudSoda/sddl \
    github.com/cloudsoda/sddl
  do
    case "$candidate" in
      "$forbidden"|"$forbidden"/*) return 0 ;;
    esac
  done
  return 1
}

is_unreviewed_smb2_path() {
  local candidate=$1
  [[ "$candidate" != "$expected_path" ]] || return 1
  case "$candidate" in
    */go-smb2|*/go-smb2/*) return 0 ;;
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
      '{{.Path}}|{{.Version}}{{with .Replace}}|{{.Path}}|{{.Version}}{{end}}' \
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
while IFS='|' read -r module_path module_version replace_path replace_version extra; do
  [[ -n "$module_path" ]] || fail 'module graph contains an empty path'
  [[ "$module_path" != *[[:space:]]* ]] || fail 'module path contains whitespace'
  [[ "$module_version" != *[[:space:]]* ]] || fail 'module version contains whitespace'
  [[ -z "${extra:-}" ]] || fail "module record has extra fields: $module_path"
  if [[ -n "${replace_path:-}" ]]; then
    [[ "$replace_path" != *[[:space:]]* ]] || fail 'replacement path contains whitespace'
  fi
  [[ "${replace_version:-}" != *[[:space:]]* ]] ||
    fail 'replacement version contains whitespace'
  [[ -z "${replace_version:-}" || -n "${replace_path:-}" ]] ||
    fail 'replacement version is missing its path'

  record_count=$((record_count + 1))
  [[ "$record_count" -le 2048 ]] || fail 'module graph exceeds the record limit'

  if is_forbidden_path "$module_path"; then
    fail "forbidden module selected: $module_path"
  fi
  if [[ -n "${replace_path:-}" ]] && is_forbidden_path "$replace_path"; then
    fail "forbidden replacement selected: $replace_path"
  fi
  if is_unreviewed_smb2_path "$module_path"; then
    fail "unreviewed SMB2 module selected: $module_path"
  fi
  if [[ -n "${replace_path:-}" ]] && is_unreviewed_smb2_path "$replace_path"; then
    fail "unreviewed SMB2 replacement selected: $replace_path"
  fi

  if [[ "$module_path" == "$expected_path" ]]; then
    [[ -z "${replace_path:-}" ]] || fail 'reviewed SMB2 module must not be replaced'
    [[ "$module_version" == "$expected_version" ]] ||
      fail "reviewed SMB2 module has unexpected version: $module_version"
    expected_count=$((expected_count + 1))
  elif [[ -n "${replace_path:-}" && "$replace_path" == "$expected_path" ]]; then
    fail 'reviewed SMB2 module must be selected directly, not as a replacement'
  fi
done <<<"$module_graph"

[[ "$record_count" -gt 0 ]] || fail 'module graph contains no records'
[[ "$expected_count" == 1 ]] ||
  fail "reviewed SMB2 module count is $expected_count, want 1"

printf 'SMB2 module boundary passed: %s@%s\n' "$expected_path" "$expected_version"
