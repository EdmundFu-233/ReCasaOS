#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Go dependency boundary fixture tests failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
checker_source="$script_directory/check-go-dependency-boundary.go"
fixtures="$script_directory/testdata/go-dependency-boundary"

command -v go >/dev/null 2>&1 || fail "go is unavailable"
[[ -f "$checker_source" && ! -L "$checker_source" ]] ||
  fail "structured dependency checker is missing or symbolic"
[[ -d "$fixtures" && ! -L "$fixtures" ]] ||
  fail "fixture directory is missing or symbolic"

workspace="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-go-dependency-fixtures.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT
mkdir -m 0700 -- "$workspace/go-build-cache"
checker="$workspace/check-go-dependency-boundary"

if ! (cd -- "$repository" && env \
  GOCACHE="$workspace/go-build-cache" \
  GOWORK=off \
  go build -mod=readonly -trimpath -o "$checker" "$checker_source"); then
  fail "could not build the structured dependency checker"
fi
[[ -x "$checker" ]] || fail "structured dependency checker was not produced"

expect_acceptance() {
  local label=$1
  local fixture=$2
  local result="$workspace/${label}.log"

  if ! "$checker" -label "$label" "$fixture" >"$result" 2>&1; then
    sed -n '1,80p' "$result" >&2
    fail "safe fixture was rejected: $label"
  fi
  grep -Fq 'Go dependency boundary check passed' "$result" ||
    fail "safe fixture did not report success: $label"
}

expect_rejection() {
  local label=$1
  local fixture=$2
  local expected=$3
  local result="$workspace/${label}.log"

  if "$checker" -label "$label" "$fixture" >"$result" 2>&1; then
    fail "unsafe fixture was accepted: $label"
  fi
  grep -Fq -- "$expected" "$result" || {
    sed -n '1,80p' "$result" >&2
    fail "rejection reason was not preserved: $label"
  }
}

for fixture in \
  allowed.json \
  forbidden-root.json \
  forbidden-subpackage.json \
  forbidden-test-variant.json \
  incomplete.json \
  load-error.json \
  dependency-errors.json \
  duplicate-key.json \
  escaped-forbidden.json \
  surrogate.json \
  bidi.json \
  whitespace-path.json \
  malformed-test-variant.json \
  malformed.json.invalid \
  empty.json.invalid
do
  [[ -f "$fixtures/$fixture" && ! -L "$fixtures/$fixture" ]] ||
    fail "required fixture is missing or symbolic: $fixture"
done

# The allowed fixture deliberately contains the forbidden text in a non-path
# JSON field and selects x/crypto/ssh. A text grep would reject it incorrectly.
expect_acceptance allowed "$fixtures/allowed.json"
expect_rejection \
  forbidden-root \
  "$fixtures/forbidden-root.json" \
  'forbidden selected package: golang.org/x/crypto/openpgp'
expect_rejection \
  forbidden-subpackage \
  "$fixtures/forbidden-subpackage.json" \
  'forbidden selected package: golang.org/x/crypto/openpgp/packet'
expect_rejection \
  forbidden-test-variant \
  "$fixtures/forbidden-test-variant.json" \
  'forbidden selected package: golang.org/x/crypto/openpgp/armor'
expect_rejection \
  incomplete \
  "$fixtures/incomplete.json" \
  'selected package graph is incomplete'
expect_rejection \
  load-error \
  "$fixtures/load-error.json" \
  'contains a load error'
expect_rejection \
  dependency-errors \
  "$fixtures/dependency-errors.json" \
  'contains dependency load errors'
expect_rejection \
  duplicate-key \
  "$fixtures/duplicate-key.json" \
  'contains duplicate key "ImportPath"'
expect_rejection \
  escaped-forbidden \
  "$fixtures/escaped-forbidden.json" \
  'forbidden selected package: golang.org/x/crypto/openpgp'
expect_rejection \
  surrogate \
  "$fixtures/surrogate.json" \
  'non-ASCII ImportPath'
expect_rejection \
  whitespace-path \
  "$fixtures/whitespace-path.json" \
  'invalid ImportPath'
expect_rejection \
  bidi \
  "$fixtures/bidi.json" \
  'non-ASCII ImportPath'
expect_rejection \
  malformed-test-variant \
  "$fixtures/malformed-test-variant.json" \
  'malformed test ImportPath'
expect_rejection \
  malformed \
  "$fixtures/malformed.json.invalid" \
  'decode package record'
expect_rejection empty "$fixtures/empty.json.invalid" 'selected package graph is empty'
printf '%s\n' \
  '{"ImportPath":"example.com/safe","Incomplete":true,"Incomplete":false}' \
  >"$workspace/duplicate-incomplete.json"
expect_rejection \
  duplicate-incomplete \
  "$workspace/duplicate-incomplete.json" \
  'contains duplicate key "Incomplete"'
printf '%s\n' \
  '{"ImportPath":"example.com/safe","Error":{"Err":"failure"},"Error":null}' \
  >"$workspace/duplicate-error.json"
expect_rejection \
  duplicate-error \
  "$workspace/duplicate-error.json" \
  'contains duplicate key "Error"'
printf '%s\n' \
  '{"ImportPath":"example.com/safe","DepsErrors":[{"Err":"failure"}],"DepsErrors":[]}' \
  >"$workspace/duplicate-deps-errors.json"
expect_rejection \
  duplicate-deps-errors \
  "$workspace/duplicate-deps-errors.json" \
  'contains duplicate key "DepsErrors"'
invalid_utf8="$workspace/invalid-utf8.json"
printf '{"ImportPath":"example.com/\377"}\n' >"$invalid_utf8"
expect_rejection invalid-utf8 "$invalid_utf8" 'not valid UTF-8'
if ! "$checker" -label stdin-allowed - \
  <"$fixtures/allowed.json" >"$workspace/stdin-allowed.log" 2>&1; then
  fail 'safe standard-input graph was rejected'
fi
if "$checker" -label stdin-forbidden - \
  <"$fixtures/forbidden-root.json" >"$workspace/stdin-forbidden.log" 2>&1; then
  fail 'forbidden standard-input graph was accepted'
fi
grep -Fq -- 'forbidden selected package' "$workspace/stdin-forbidden.log" ||
  fail 'standard-input rejection reason was not preserved'
ln -s -- "$fixtures/allowed.json" "$workspace/symbolic-graph.json"
expect_rejection \
  symbolic-graph \
  "$workspace/symbolic-graph.json" \
  'package graph is not a regular non-symbolic file'

printf 'Go dependency boundary fixture tests passed\n'
