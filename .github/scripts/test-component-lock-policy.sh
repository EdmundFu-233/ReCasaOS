#!/usr/bin/env bash

set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'component lock policy test failed: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-component-lock-test.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

checker="$work_dir/check-component-lock"
(
  cd -- "$repo_root"
  env \
    CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOWORK=off \
    go build -mod=readonly -trimpath -o "$checker" \
      "$script_dir/check-component-lock.go"
)

primary_config="$work_dir/goreleaser.yaml"
debug_config="$work_dir/goreleaser.debug.yaml"
cp -- "$repo_root/.goreleaser.yaml" "$primary_config"
cp -- "$repo_root/.goreleaser.debug.yaml" "$debug_config"

accepted=0
rejected=0

expect_accept() {
  local name=$1
  local manifest=$2
  local primary=${3:-$primary_config}
  local debug=${4:-$debug_config}
  if ! "$checker" \
    --manifest "$manifest" \
    --goreleaser "$primary" \
    --goreleaser-debug "$debug" \
    >"$work_dir/stdout" 2>"$work_dir/stderr"
  then
    printf 'positive case %s unexpectedly failed:\n' "$name" >&2
    sed -n '1,80p' "$work_dir/stderr" >&2
    exit 1
  fi
  accepted=$((accepted + 1))
}

expect_reject() {
  local name=$1
  local manifest=$2
  local primary=${3:-$primary_config}
  local debug=${4:-$debug_config}
  if "$checker" \
    --manifest "$manifest" \
    --goreleaser "$primary" \
    --goreleaser-debug "$debug" \
    >"$work_dir/stdout" 2>"$work_dir/stderr"
  then
    fail "negative case $name was accepted"
  fi
  rejected=$((rejected + 1))
}

manifest="$repo_root/release/components.lock.json"
locked_fixture="$script_dir/testdata/component-lock-one-locked.json"
all_locked_fixture="$script_dir/testdata/component-lock-all-locked.json"
expect_accept current-unresolved-hold "$manifest"
expect_accept one-structural-lock-hold "$locked_fixture"
expect_accept all-structural-locks-hold "$all_locked_fixture"

mutated="$work_dir/mutated.json"

awk '
  BEGIN { removing = 0; removed = 0 }
  !removed && /^    \{$/ { removing = 1; next }
  removing && /^    \},$/ { removing = 0; removed = 1; next }
  !removing { print }
' "$manifest" >"$mutated"
expect_reject missing-required-component "$mutated"

sed 's/"name": "installer"/"name": "not-installer"/' \
  "$manifest" >"$mutated"
expect_reject unknown-component "$mutated"

sed 's/"name": "installer"/"name": "gateway"/' \
  "$manifest" >"$mutated"
expect_reject duplicate-component "$mutated"

sed \
  -e 's/"name": "app-management"/"name": "component-swap"/' \
  -e 's/"name": "gateway"/"name": "app-management"/' \
  -e 's/"name": "component-swap"/"name": "gateway"/' \
  "$manifest" >"$mutated"
expect_reject noncanonical-component-order "$mutated"

sed 's/"source_revision": "1111111111111111111111111111111111111111"/"source_revision": "main"/' \
  "$locked_fixture" >"$mutated"
expect_reject moving-source-reference "$mutated"

sed 's/"source_revision": "1111111111111111111111111111111111111111"/"source_revision": "abc123"/' \
  "$locked_fixture" >"$mutated"
expect_reject malformed-source-revision "$mutated"

sed 's/"artifact_sha256": "2222222222222222222222222222222222222222222222222222222222222222"/"artifact_sha256": "1234"/' \
  "$locked_fixture" >"$mutated"
expect_reject malformed-artifact-digest "$mutated"

sed 's|"source_repository": "https:|"source_repository": "http:|' \
  "$locked_fixture" >"$mutated"
expect_reject non-https-source-repository "$mutated"

sed 's/"license": "Apache-2.0"/"license": null/' \
  "$locked_fixture" >"$mutated"
expect_reject missing-license "$mutated"

sed 's/"api_schema": "not-applicable"/"api_schema": null/' \
  "$locked_fixture" >"$mutated"
expect_reject missing-api-schema "$mutated"

sed 's/"compatibility_status": "passed"/"compatibility_status": null/' \
  "$locked_fixture" >"$mutated"
expect_reject missing-compatibility-status "$mutated"

sed \
  's/"state": "locked",/"state": "unresolved", "reason": "fixture retains forbidden lock material",/' \
  "$locked_fixture" >"$mutated"
expect_reject unresolved-component-with-pin "$mutated"

sed 's/  disable: true/  disable: false/' \
  "$repo_root/.goreleaser.yaml" >"$work_dir/enabled-primary.yaml"
expect_reject unresolved-with-primary-release-enabled \
  "$manifest" "$work_dir/enabled-primary.yaml" "$debug_config"

sed 's/  disable: true/  disable: false/' \
  "$repo_root/.goreleaser.debug.yaml" >"$work_dir/enabled-debug.yaml"
expect_reject unresolved-with-debug-release-enabled \
  "$manifest" "$primary_config" "$work_dir/enabled-debug.yaml"

expect_reject all-locked-with-release-enabled \
  "$all_locked_fixture" "$work_dir/enabled-primary.yaml" "$debug_config"

sed 's/"schema_version": 1/"schema_version": 2/' \
  "$manifest" >"$mutated"
expect_reject unknown-schema-version "$mutated"

sed '/"publication_state": "hold",/d' \
  "$manifest" >"$mutated"
expect_reject missing-publication-state "$mutated"

sed 's/"publication_state": "hold"/"publication_state": "ready"/' \
  "$manifest" >"$mutated"
expect_reject ready-publication-state "$mutated"

sed 's/"publication_state": "hold"/"publication_state": "paused"/' \
  "$manifest" >"$mutated"
expect_reject unknown-publication-state "$mutated"

sed 's/"schema_version": 1/"schema_version": 1, "unknown": true/' \
  "$manifest" >"$mutated"
expect_reject unknown-manifest-field "$mutated"

sed 's/"schema_version": 1/"schema_version": 1, "schema_version": 1/' \
  "$manifest" >"$mutated"
expect_reject duplicate-json-key "$mutated"

{
  printf '%s' '{"schema_version":1,"publication_state":"hold","components":[],"bad'
  printf '\377'
  printf '%s\n' '":true}'
} >"$mutated"
expect_reject invalid-utf8-manifest "$mutated"
grep -Fq 'component lock must be valid UTF-8' "$work_dir/stderr" ||
  fail "invalid UTF-8 was not rejected before JSON decoding"

sed 's/"schema_version": 1/"Schema_Version": 1/' \
  "$manifest" >"$mutated"
expect_reject alternate-case-schema-version-key "$mutated"
grep -Fq 'unknown key "Schema_Version"' "$work_dir/stderr" ||
  fail "alternate-case schema key was not rejected by the exact JSON schema"

sed 's/"publication_state": "hold"/"Publication_State": "hold"/' \
  "$manifest" >"$mutated"
expect_reject alternate-case-publication-state-key "$mutated"
grep -Fq 'unknown key "Publication_State"' "$work_dir/stderr" ||
  fail "alternate-case publication key was not rejected by the exact JSON schema"

sed 's/"name": "installer"/"Name": "installer"/' \
  "$manifest" >"$mutated"
expect_reject alternate-case-component-name-key "$mutated"
grep -Fq 'unknown key "Name"' "$work_dir/stderr" ||
  fail "alternate-case component name key was not rejected by the exact JSON schema"

sed 's/"state": "unresolved"/"State": "unresolved"/' \
  "$manifest" >"$mutated"
expect_reject alternate-case-component-state-key "$mutated"
grep -Fq 'unknown key "State"' "$work_dir/stderr" ||
  fail "alternate-case component state key was not rejected by the exact JSON schema"

sed 's/"schema_version": 1/"schema_version": 999, "Schema_Version": 1/' \
  "$manifest" >"$mutated"
expect_reject mixed-case-schema-semantic-duplicate "$mutated"
grep -Fq 'unknown key "Schema_Version"' "$work_dir/stderr" ||
  fail "mixed-case schema duplicate was not rejected by the exact JSON schema"

sed \
  's/"name": "app-management"/"name": "not-app-management", "Name": "app-management"/' \
  "$locked_fixture" >"$mutated"
expect_reject mixed-case-component-name-semantic-duplicate "$mutated"
grep -Fq 'unknown key "Name"' "$work_dir/stderr" ||
  fail "mixed-case component duplicate was not rejected by the exact JSON schema"

printf '%s\n' \
  'release: { disable: true }' \
  '"release": { disable: false }' \
  >"$work_dir/duplicate-release.yaml"
expect_reject alternate-duplicate-release-key \
  "$manifest" "$work_dir/duplicate-release.yaml" "$debug_config"

printf '%s\n' \
  'release:' \
  '  disable: true' \
  '  "disable": false' \
  >"$work_dir/duplicate-disable.yaml"
expect_reject alternate-duplicate-disable-key \
  "$manifest" "$work_dir/duplicate-disable.yaml" "$debug_config"

printf '%s\n' \
  '---' \
  'release: { disable: false }' \
  '---' \
  'release:' \
  '  disable: true' \
  >"$work_dir/first-false-second-true.yaml"
expect_reject first-document-false-second-document-true \
  "$manifest" "$work_dir/first-false-second-true.yaml" "$debug_config"

printf '%s\n' \
  'release:' \
  '  disable: true' \
  '---' \
  'release:' \
  '  disable: false' \
  >"$work_dir/first-true-second-false.yaml"
expect_reject first-document-true-second-document-false \
  "$manifest" "$work_dir/first-true-second-false.yaml" "$debug_config"

printf '%s\n' \
  '---   # first document start' \
  'release:' \
  '  disable: true' \
  '---   # second document start' \
  'release:' \
  '  disable: true' \
  >"$work_dir/commented-document-start.yaml"
expect_reject commented-multiple-document-start \
  "$manifest" "$work_dir/commented-document-start.yaml" "$debug_config"

printf '%s\n' \
  'release:' \
  '  disable: true' \
  '... # first document end' \
  '--- # second document start' \
  'release:' \
  '  disable: true' \
  >"$work_dir/commented-document-end.yaml"
expect_reject commented-multiple-document-end \
  "$manifest" "$work_dir/commented-document-end.yaml" "$debug_config"

printf '%s\n' \
  'release:' \
  '  <<: {disable: false}' \
  '  footer: "x' \
  '  disable: true' \
  '  "' \
  >"$work_dir/merge-with-quoted-pseudo-field.yaml"
expect_reject release-merge-with-quoted-pseudo-disable \
  "$manifest" "$work_dir/merge-with-quoted-pseudo-field.yaml" "$debug_config"
grep -Fq 'release contains a forbidden YAML merge key' "$work_dir/stderr" ||
  fail "release merge attack was not rejected by semantic YAML policy"

printf '%s\n' \
  'release:' \
  '  "\u0064isable": false' \
  '  footer: "x' \
  '  disable: true' \
  '  "' \
  >"$work_dir/escaped-key-with-quoted-pseudo-field.yaml"
expect_reject escaped-disable-key-with-quoted-pseudo-disable \
  "$manifest" "$work_dir/escaped-key-with-quoted-pseudo-field.yaml" "$debug_config"
grep -Fq 'release.disable must be an explicit YAML boolean true' "$work_dir/stderr" ||
  fail "escaped disable key was not interpreted with YAML string semantics"

printf '%s\n' \
  'release: { disable: false }' \
  'footer: "x' \
  '  disable: true' \
  '  "' \
  >"$work_dir/flow-release-with-quoted-pseudo-field.yaml"
expect_reject flow-release-false-with-quoted-pseudo-disable \
  "$manifest" "$work_dir/flow-release-with-quoted-pseudo-field.yaml" "$debug_config"
grep -Fq 'release.disable must be an explicit YAML boolean true' "$work_dir/stderr" ||
  fail "flow release false value was not interpreted with YAML mapping semantics"

printf '%s\n' \
  'release: { disable: "true" }' \
  >"$work_dir/string-disable.yaml"
expect_reject string-true-is-not-boolean-true \
  "$manifest" "$work_dir/string-disable.yaml" "$debug_config"
grep -Fq 'release.disable must be an explicit YAML boolean true' "$work_dir/stderr" ||
  fail "string true was not rejected by the strict YAML boolean policy"

printf '%s\n' \
  'defaults: &release_defaults' \
  '  disable: true' \
  'release: *release_defaults' \
  >"$work_dir/release-alias.yaml"
expect_reject release-alias \
  "$manifest" "$work_dir/release-alias.yaml" "$debug_config"
grep -Fq 'release contains a forbidden YAML alias' "$work_dir/stderr" ||
  fail "release alias was not rejected by the explicit alias policy"

{
  printf '%b' '\357\273\277'
  printf '%s\n' \
    'release:' \
    '  disable: true'
} >"$work_dir/bom-at-file-start.yaml"
expect_reject bom-at-file-start \
  "$manifest" "$work_dir/bom-at-file-start.yaml" "$debug_config"
grep -Fq 'forbidden UTF-8 byte-order mark' "$work_dir/stderr" ||
  fail "file-start BOM was not rejected by the explicit BOM policy"

{
  printf '%s\n' \
    'release: { disable: false }'
  printf '%b\n' '\357\273\277---'
  printf '%s\n' \
    'release:' \
    '  disable: true'
} >"$work_dir/bom-before-second-document.yaml"
expect_reject first-false-bom-second-document-marker \
  "$manifest" "$work_dir/bom-before-second-document.yaml" "$debug_config"
grep -Fq 'forbidden UTF-8 byte-order mark' "$work_dir/stderr" ||
  fail "second-document BOM was not rejected by the explicit BOM policy"

printf 'component lock policy tests passed: accepted=%d rejected=%d\n' \
  "$accepted" "$rejected"
