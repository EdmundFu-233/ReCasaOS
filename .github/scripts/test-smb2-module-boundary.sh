#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'SMB2 module boundary fixture tests failed: %s\n' "$*" >&2
  exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
checker="$script_dir/check-smb2-module-boundary.sh"
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
  grep -Fq 'SMB2 module boundary passed' "$workspace/$name.out" ||
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

expected='github.com/EdmundFu-233/go-smb2'
version='v1.1.1-recasaos.1'

write_fixture allowed \
  'github.com/IceWhaleTech/CasaOS|' \
  "$expected|$version" \
  'golang.org/x/crypto|v0.55.0'
expect_pass allowed

write_fixture missing 'github.com/IceWhaleTech/CasaOS|'
expect_fail missing 'reviewed SMB2 module count is 0'

write_fixture duplicate \
  "$expected|$version" \
  "$expected|$version"
expect_fail duplicate 'reviewed SMB2 module count is 2'

write_fixture wrong-version "$expected|v1.1.0"
expect_fail wrong-version 'unexpected version'

write_fixture replaced-reviewed \
  "$expected|$version|github.com/example/smb-client|v1.0.0"
expect_fail replaced-reviewed 'must not be replaced'

write_fixture reviewed-as-replacement \
  "github.com/example/smb-client|v1.0.0|$expected|$version"
expect_fail reviewed-as-replacement 'must be selected directly'

for forbidden_name in old-hiro cloud-soda lowercase-cloud-soda sddl lowercase-sddl; do
  case "$forbidden_name" in
    old-hiro) forbidden='github.com/hirochachacha/go-smb2' ;;
    cloud-soda) forbidden='github.com/CloudSoda/go-smb2' ;;
    lowercase-cloud-soda) forbidden='github.com/cloudsoda/go-smb2' ;;
    sddl) forbidden='github.com/CloudSoda/sddl' ;;
    lowercase-sddl) forbidden='github.com/cloudsoda/sddl' ;;
  esac
  write_fixture "$forbidden_name" \
    "$expected|$version" \
    "$forbidden|v1.0.0"
  expect_fail "$forbidden_name" 'forbidden module selected'
done

write_fixture forbidden-submodule \
  "$expected|$version" \
  'github.com/hirochachacha/go-smb2/v2|v2.0.0'
expect_fail forbidden-submodule 'forbidden module selected'

write_fixture unreviewed-fork \
  "$expected|$version" \
  'github.com/example/go-smb2|v1.1.1'
expect_fail unreviewed-fork 'unreviewed SMB2 module selected'

write_fixture extra-field "$expected|$version|||extra"
expect_fail extra-field 'extra fields'

write_fixture malformed-replacement "$expected|$version||v1.0.0"
expect_fail malformed-replacement 'replacement version is missing its path'

write_fixture forbidden-replacement \
  "$expected|$version" \
  'github.com/example/module|v1.0.0|github.com/hirochachacha/go-smb2|v1.1.0'
expect_fail forbidden-replacement 'forbidden replacement selected'

write_fixture unreviewed-replacement \
  "$expected|$version" \
  'github.com/example/module|v1.0.0|github.com/example/go-smb2|v1.1.1'
expect_fail unreviewed-replacement 'unreviewed SMB2 replacement selected'

write_fixture empty
expect_fail empty 'module graph is empty'

write_fixture empty-path \
  "$expected|$version" \
  '|v1.0.0'
expect_fail empty-path 'empty path'

ln -s "$workspace/allowed.modules" "$workspace/symlink.modules"
expect_fail symlink 'regular non-symlink file'

dd if=/dev/zero of="$workspace/oversized.modules" bs=1024 count=1025 2>/dev/null
expect_fail oversized 'exceeds the 1 MiB limit'

{
  printf '%s\n' "$expected|$version"
  for ((record_index = 0; record_index < 2048; record_index++)); do
    printf 'github.com/example/module-%d|v1.0.0\n' "$record_index"
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

printf 'SMB2 module boundary fixture tests passed\n'
