#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'Gorilla WebSocket module boundary fixture tests failed: %s\n' "$*" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
checker="$script_dir/check-gorilla-websocket-module-boundary.sh"
workspace=$(mktemp -d)
trap 'rm -rf -- "$workspace"' EXIT HUP INT TERM

write_fixture() {
  local name=$1
  shift
  printf '%s\n' "$@" >"$workspace/$name.modules"
}

expect_pass() {
  local name=$1
  if ! "$checker" --input "$workspace/$name.modules" >"$workspace/$name.out" 2>"$workspace/$name.err"; then
    sed -n '1,20p' "$workspace/$name.err" >&2
    fail "$name unexpectedly failed"
  fi
  grep -Fq 'Gorilla WebSocket module boundary passed' "$workspace/$name.out" ||
    fail "$name omitted the success marker"
  [[ ! -s "$workspace/$name.err" ]] || fail "$name wrote unexpected stderr"
}

expect_fail() {
  local name=$1
  local reason=$2
  if "$checker" --input "$workspace/$name.modules" >"$workspace/$name.out" 2>"$workspace/$name.err"; then
    fail "$name unexpectedly passed"
  fi
  grep -Fq "$reason" "$workspace/$name.err" ||
    fail "$name failed for the wrong reason"
}

expect_repository_guard_fail() {
  local name=$1
  local guarded_path=$2
  local kind=$3
  local reason=$4
  local repository="$workspace/$name.repository"
  mkdir -p "$repository/.github/scripts"
  cp "$checker" "$repository/.github/scripts/"
  printf '%s\n' 'module github.com/IceWhaleTech/CasaOS' >"$repository/go.mod"
  case "$kind" in
    directory) mkdir "$repository/$guarded_path" ;;
    file) printf '%s\n' 'blocked fixture' >"$repository/$guarded_path" ;;
    symlink) ln -s missing-target "$repository/$guarded_path" ;;
    *) fail "unknown repository guard fixture kind: $kind" ;;
  esac

  if "$repository/.github/scripts/check-gorilla-websocket-module-boundary.sh" \
    --input "$workspace/allowed.modules" \
    >"$workspace/$name.out" 2>"$workspace/$name.err"
  then
    fail "$name unexpectedly passed"
  fi
  grep -Fq "$reason" "$workspace/$name.err" ||
    fail "$name failed for the wrong reason"
}

expected='github.com/gorilla/websocket'
version='v1.5.4-0.20240701034025-d67f41855da4'
sum='h1:PYKzliEgITjLJoJqbV90S0YRaG8LNAsICH6fp6MApC0='
go_mod_sum='h1:r4w70xmWCQKmi1ONH4KIaBptdivuRPyosB9RmPlGEwA='

write_fixture allowed \
  'github.com/IceWhaleTech/CasaOS|||' \
  "$expected|$version|$sum|$go_mod_sum"
expect_pass allowed

expect_repository_guard_fail vendor-directory vendor directory \
  'vendor directory or link is not allowed'
expect_repository_guard_fail vendor-symlink vendor symlink \
  'vendor directory or link is not allowed'
expect_repository_guard_fail workspace-file go.work file \
  'go.work file or link is not allowed'
expect_repository_guard_fail workspace-sum-symlink go.work.sum symlink \
  'go.work.sum file or link is not allowed'

write_fixture false-fixed-version "$expected|v1.5.3|$sum|$go_mod_sum"
expect_fail false-fixed-version 'unexpected version: v1.5.3'

write_fixture vulnerable-version "$expected|v1.5.0|$sum|$go_mod_sum"
expect_fail vulnerable-version 'unexpected version: v1.5.0'

write_fixture wrong-pseudo-version \
  "$expected|v1.5.4-0.20240701034025-d67f41855da5|$sum|$go_mod_sum"
expect_fail wrong-pseudo-version 'unexpected version'

write_fixture wrong-zip-sum "$expected|$version|h1:wrong|$go_mod_sum"
expect_fail wrong-zip-sum 'unexpected zip checksum'

write_fixture wrong-go-mod-sum "$expected|$version|$sum|h1:wrong"
expect_fail wrong-go-mod-sum 'unexpected go.mod checksum'

write_fixture missing 'github.com/IceWhaleTech/CasaOS|||'
expect_fail missing 'reviewed Gorilla WebSocket module count is 0'

write_fixture duplicate \
  "$expected|$version|$sum|$go_mod_sum" \
  "$expected|$version|$sum|$go_mod_sum"
expect_fail duplicate 'reviewed Gorilla WebSocket module count is 2'

write_fixture replaced-reviewed \
  "$expected|$version|$sum|$go_mod_sum|github.com/example/fork|v1.0.0|h1:fork|h1:forkmod"
expect_fail replaced-reviewed 'must not be replaced'

write_fixture reviewed-as-replacement \
  "github.com/example/fork|v1.0.0|h1:fork|h1:forkmod|$expected|$version|$sum|$go_mod_sum"
expect_fail reviewed-as-replacement 'must be selected directly'

write_fixture alternate-major \
  "$expected|$version|$sum|$go_mod_sum" \
  "$expected/v2|v2.0.0|h1:v2|h1:v2mod"
expect_fail alternate-major 'unreviewed Gorilla WebSocket module selected'

write_fixture renamed-fork \
  "$expected|$version|$sum|$go_mod_sum" \
  'github.com/example/websocket|v9.9.9|h1:fork|h1:forkmod'
expect_fail renamed-fork 'unreviewed Gorilla WebSocket module selected'

write_fixture alternate-replacement \
  "$expected|$version|$sum|$go_mod_sum" \
  "github.com/example/module|v1.0.0|h1:example|h1:examplemod|$expected/v2|v2.0.0|h1:v2|h1:v2mod"
expect_fail alternate-replacement 'unreviewed Gorilla WebSocket replacement selected'

write_fixture renamed-fork-replacement \
  "$expected|$version|$sum|$go_mod_sum" \
  'github.com/example/module|v1.0.0|h1:example|h1:examplemod|github.com/example/websocket|v9.9.9|h1:fork|h1:forkmod'
expect_fail renamed-fork-replacement 'unreviewed Gorilla WebSocket replacement selected'

write_fixture extra-field "$expected|$version|$sum|$go_mod_sum|||||extra"
expect_fail extra-field 'extra fields'

write_fixture malformed-replacement "$expected|$version|$sum|$go_mod_sum||v1.0.0||"
expect_fail malformed-replacement 'replacement metadata is missing its path'

write_fixture whitespace-path \
  "$expected|$version|$sum|$go_mod_sum" \
  'github.com/example/bad path|v1.0.0|h1:example|h1:examplemod'
expect_fail whitespace-path 'module record contains whitespace'

write_fixture empty
expect_fail empty 'module graph is empty'

write_fixture empty-path \
  "$expected|$version|$sum|$go_mod_sum" \
  '|v1.0.0|h1:example|h1:examplemod'
expect_fail empty-path 'empty path'

ln -s "$workspace/allowed.modules" "$workspace/symlink.modules"
expect_fail symlink 'regular non-symlink file'

dd if=/dev/zero of="$workspace/oversized.modules" bs=1024 count=1025 2>/dev/null
expect_fail oversized 'exceeds the 1 MiB limit'

{
  printf '%s\n' "$expected|$version|$sum|$go_mod_sum"
  for ((record_index = 0; record_index < 2048; record_index++)); do
    printf 'github.com/example/module-%d|v1.0.0|h1:example|h1:examplemod\n' "$record_index"
  done
} >"$workspace/too-many.modules"
expect_fail too-many 'exceeds the record limit'

mkdir "$workspace/bin"
printf '%s\n' '#!/bin/sh' 'exit 23' >"$workspace/bin/go"
chmod 0755 "$workspace/bin/go"
if PATH="$workspace/bin:$PATH" "$checker" >"$workspace/go-list-failure.out" 2>"$workspace/go-list-failure.err"; then
  fail 'go-list-failure unexpectedly passed'
fi
grep -Fq 'go list could not produce the complete module graph' \
  "$workspace/go-list-failure.err" || fail 'go-list-failure failed for the wrong reason'

verify_repository="$workspace/verify-failure.repository"
mkdir -p "$verify_repository/.github/scripts" "$verify_repository/bin"
cp "$checker" "$verify_repository/.github/scripts/"
printf '%s\n' 'module github.com/IceWhaleTech/CasaOS' >"$verify_repository/go.mod"
{
  printf '%s\n' '#!/bin/sh' 'set -eu'
  printf '%s\n' 'case "$1" in'
  printf '%s\n' '  list)'
  printf '%s\n' "    printf '%s\\n' 'github.com/IceWhaleTech/CasaOS|||' \"\$FAKE_EXPECTED|\$FAKE_VERSION|\$FAKE_SUM|\$FAKE_GO_MOD_SUM\""
  printf '%s\n' '    ;;'
  printf '%s\n' '  mod)'
  printf '%s\n' '    if [ "$2" = download ]; then exit 0; fi'
  printf '%s\n' '    if [ "$2" = verify ]; then printf '\''tampered module cache\\n'\'' >&2; exit 23; fi'
  printf '%s\n' '    exit 24'
  printf '%s\n' '    ;;'
  printf '%s\n' '  *) exit 25 ;;'
  printf '%s\n' 'esac'
} >"$verify_repository/bin/go"
chmod 0755 "$verify_repository/bin/go"
if FAKE_EXPECTED="$expected" \
  FAKE_VERSION="$version" \
  FAKE_SUM="$sum" \
  FAKE_GO_MOD_SUM="$go_mod_sum" \
  PATH="$verify_repository/bin:$PATH" \
  "$verify_repository/.github/scripts/check-gorilla-websocket-module-boundary.sh" \
  >"$workspace/verify-failure.out" 2>"$workspace/verify-failure.err"
then
  fail 'verify-failure unexpectedly passed'
fi
grep -Fq 'module cache verification failed' "$workspace/verify-failure.err" ||
  fail 'verify-failure failed for the wrong reason'

printf 'Gorilla WebSocket module boundary fixture tests passed\n'
