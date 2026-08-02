#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

die() {
  printf 'trusted privileged workflow negative tests failed: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
checker="$script_dir/check-trusted-privileged-workflow.sh"
workflow="$repo_root/.github/workflows/trusted-privileged-ci.yml"

[[ -x "$checker" ]] || die "checker is not executable"
[[ -f "$workflow" ]] || die "workflow is missing"
command -v perl >/dev/null 2>&1 || die "perl is unavailable"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-trusted-ci.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

"$checker" "$workflow"

replace_once() {
  local file="$1"
  local needle="$2"
  local replacement="$3"
  NEEDLE="$needle" REPLACEMENT="$replacement" perl -0pi -e '
    BEGIN {
      $needle = $ENV{"NEEDLE"};
      $replacement = $ENV{"REPLACEMENT"};
    }
    $offset = index($_, $needle);
    die "test mutation target is missing\n" if $offset < 0;
    substr($_, $offset, length($needle), $replacement);
  ' "$file"
}

expect_rejection() {
  local label="$1"
  local needle="$2"
  local replacement="$3"
  local candidate="$work_dir/${label}.yml"

  cp -- "$workflow" "$candidate"
  replace_once "$candidate" "$needle" "$replacement"
  if "$checker" "$candidate" >"$work_dir/${label}.log" 2>&1; then
    die "unsafe mutation was accepted: $label"
  fi
}

expect_rejection pull-request-target \
  '  workflow_run:' \
  $'  pull_request_target:\n  workflow_run:'
expect_rejection persisted-checkout-credential \
  '          persist-credentials: false' \
  '          persist-credentials: true'
expect_rejection shared-cache \
  '          cache: false' \
  '          cache: true'
expect_rejection write-token-on-runner \
  $'  privileged-promotion:\n    name: Run promoted privileged matrix\n    needs:\n      - prepare-promotion\n    runs-on: ubuntu-24.04\n    timeout-minutes: 25\n    permissions:\n      contents: read' \
  $'  privileged-promotion:\n    name: Run promoted privileged matrix\n    needs:\n      - prepare-promotion\n    runs-on: ubuntu-24.04\n    timeout-minutes: 25\n    permissions:\n      contents: write'
expect_rejection checkout-in-writer \
  '      # This write-capable job intentionally has no checkout step.' \
  $'      - uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd\n      # unsafe checkout'
expect_rejection stale-head-attestation \
  '          [[ "$current_head" == "$RUN_HEAD_SHA" ]]' \
  '          [[ -n "$current_head" ]]'
expect_rejection unbound-pr-association \
  '                .head.sha == $head_sha' \
  '                .head.sha != $head_sha'
expect_rejection unpinned-tree \
  '          [[ "$actual_tree" == "$EXPECTED_TREE" ]]' \
  '          [[ -n "$actual_tree" ]]'
expect_rejection mount-matrix-drift \
  'TestManagedDirectDirectoryRenameRejectsNestedBindMount|' \
  'TestManagedDirectDirectoryRenameRejectsNestedBindMount_REMOVED|'
expect_rejection unsafe-cleanup \
  '          [[ "$pinned_sha" == "$EXPECTED_SHA" ]] || {' \
  '          [[ -n "$pinned_sha" ]] || {'
expect_rejection changed-trusted-workflow \
  '            [[ "$head_policy_blob" == "$default_policy_blob" ]]' \
  '            [[ -n "$head_policy_blob" ]]'

printf 'trusted privileged workflow negative tests passed\n'
