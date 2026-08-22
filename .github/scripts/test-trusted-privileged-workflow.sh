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
primary_workflow="$repo_root/.github/workflows/recasaos-ci-security.yml"

[[ -x "$checker" ]] || die "checker is not executable"
[[ -f "$workflow" ]] || die "workflow is missing"
[[ -f "$primary_workflow" ]] || die "primary workflow is missing"
command -v perl >/dev/null 2>&1 || die "perl is unavailable"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-trusted-ci.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

"$checker" "$workflow" "$primary_workflow"

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

expect_workflow_rejection() {
  local label="$1"
  local target="$2"
  local needle="$3"
  local replacement="$4"
  local candidate_dir="$work_dir/$label"
  local candidate_workflow="$candidate_dir/trusted-privileged-ci.yml"
  local candidate_primary="$candidate_dir/recasaos-ci-security.yml"
  local mutation_target

  mkdir -p -- "$candidate_dir"
  cp -- "$workflow" "$candidate_workflow"
  cp -- "$primary_workflow" "$candidate_primary"
  case "$target" in
    trusted) mutation_target="$candidate_workflow" ;;
    primary) mutation_target="$candidate_primary" ;;
    *) die "unknown workflow mutation target: $target" ;;
  esac
  replace_once "$mutation_target" "$needle" "$replacement"
  if "$checker" "$candidate_workflow" "$candidate_primary" \
    >"$candidate_dir/result.log" 2>&1
  then
    die "unsafe mutation was accepted: $label"
  fi
}

expect_rejection() {
  expect_workflow_rejection "$1" trusted "$2" "$3"
}

expect_primary_rejection() {
  expect_workflow_rejection "$1" primary "$2" "$3"
}

expect_paired_rejection() {
  local label="$1"
  local needle="$2"
  local replacement="$3"
  local candidate_dir="$work_dir/$label"
  local candidate_workflow="$candidate_dir/trusted-privileged-ci.yml"
  local candidate_primary="$candidate_dir/recasaos-ci-security.yml"

  mkdir -p -- "$candidate_dir"
  cp -- "$workflow" "$candidate_workflow"
  cp -- "$primary_workflow" "$candidate_primary"
  replace_once "$candidate_workflow" "$needle" "$replacement"
  replace_once "$candidate_primary" "$needle" "$replacement"
  if "$checker" "$candidate_workflow" "$candidate_primary" \
    >"$candidate_dir/result.log" 2>&1
  then
    die "unsafe paired mutation was accepted: $label"
  fi
}

expect_double_mutation_rejection() {
  local label="$1"
  local target="$2"
  local first_needle="$3"
  local first_replacement="$4"
  local second_needle="$5"
  local second_replacement="$6"
  local candidate_dir="$work_dir/$label"
  local candidate_workflow="$candidate_dir/trusted-privileged-ci.yml"
  local candidate_primary="$candidate_dir/recasaos-ci-security.yml"
  local mutation_target

  mkdir -p -- "$candidate_dir"
  cp -- "$workflow" "$candidate_workflow"
  cp -- "$primary_workflow" "$candidate_primary"
  case "$target" in
    trusted) mutation_target="$candidate_workflow" ;;
    primary) mutation_target="$candidate_primary" ;;
    *) die "unknown workflow mutation target: $target" ;;
  esac
  replace_once "$mutation_target" "$first_needle" "$first_replacement"
  replace_once "$mutation_target" "$second_needle" "$second_replacement"
  if "$checker" "$candidate_workflow" "$candidate_primary" \
    >"$candidate_dir/result.log" 2>&1
  then
    die "unsafe compensated mutation was accepted: $label"
  fi
}

expect_rejection pull-request-target \
  '  workflow_run:' \
  $'  pull_request_target:\n  workflow_run:'
expect_rejection caller-selected-workflow-ref \
  '  repository_dispatch:' \
  $'  workflow_dispatch:\n  repository_dispatch:'
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
expect_rejection trusted-mount-matrix-drift \
  "-test.run '^(TestManagedDirectDirectoryRenameRejectsNestedBindMount|" \
  "-test.run '^(TestManagedDirectDirectoryRenameRejectsNestedBindMount_REMOVED|"
expect_primary_rejection primary-mount-matrix-drift \
  'TestWalkManagedArchiveAllowsStableNestedMount)$' \
  'TestWalkManagedArchiveAllowsStableNestedMount_REMOVED)$'
expect_paired_rejection paired-missing-test-preflight \
  $'            TestWalkManagedArchiveAllowsStableNestedMount\n          )' \
  '          )'
expect_paired_rejection paired-commented-selector \
  $'                -test.count=1 \\\n                -test.run \'^(TestManagedDirectDirectoryRenameRejectsNestedBindMount|TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling|TestManagedRootsTreeSizeRejectsNestedBindMount|TestManagedDirectoryCopyRejectsBindMountAliasIntoSource|TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot|TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot|TestWalkManagedArchiveRejectsChildMountReplacement|TestWalkManagedArchiveAllowsStableNestedMount)$\' \\\n                -test.timeout=4m \\\n                -test.v' \
  $'                -test.count=1\n                # -test.run \'^(TestManagedDirectDirectoryRenameRejectsNestedBindMount|TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling|TestManagedRootsTreeSizeRejectsNestedBindMount|TestManagedDirectoryCopyRejectsBindMountAliasIntoSource|TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot|TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot|TestWalkManagedArchiveRejectsChildMountReplacement|TestWalkManagedArchiveAllowsStableNestedMount)$\' \\\n                # -test.timeout=4m \\\n                # -test.v'
expect_rejection trusted-wide-second-test-selector \
  '                -test.timeout=4m \' \
  $'                -test.run=^.*$ \\\n                -test.timeout=4m \\'
expect_primary_rejection primary-wide-second-test-selector \
  '                -test.timeout=4m \' \
  $'                -test.run \'^.*$\' \\\n                -test.timeout=4m \\'
expect_rejection trusted-extra-filesecurity-root-invocation \
  '      - name: Exercise public-root mount and filesystem regressions' \
  $'      - name: Unsafe extra filesecurity root invocation\n        run: sudo "$RUNNER_TEMP/recasaos-filesecurity.test" -test.count=1\n\n      - name: Exercise public-root mount and filesystem regressions'
expect_primary_rejection primary-extra-filesecurity-root-invocation \
  '      - name: Exercise public-root mount and filesystem regressions' \
  $'      - name: Unsafe extra filesecurity root invocation\n        run: sudo "$RUNNER_TEMP/recasaos-filesecurity.test" -test.count=1\n\n      - name: Exercise public-root mount and filesystem regressions'
expect_double_mutation_rejection trusted-compensated-extra-invocation trusted \
  $'            "$RUNNER_TEMP/recasaos-filesecurity.test" \\\n' \
  '' \
  '      - name: Exercise public-root mount and filesystem regressions' \
  $'      - name: Compensating filesecurity root invocation\n        run: sudo "$RUNNER_TEMP/recasaos-filesecurity.test" -test.count=1\n\n      - name: Exercise public-root mount and filesystem regressions'
expect_double_mutation_rejection primary-compensated-extra-invocation primary \
  $'          test -x "$RUNNER_TEMP/recasaos-filesecurity.test"\n' \
  '' \
  '      - name: Exercise public-root mount and filesystem regressions' \
  $'      - name: Compensating filesecurity root invocation\n        run: sudo "$RUNNER_TEMP/recasaos-filesecurity.test" -test.count=1\n\n      - name: Exercise public-root mount and filesystem regressions'
expect_rejection unsafe-cleanup \
  '          [[ "$pinned_sha" == "$EXPECTED_SHA" ]] || {' \
  '          [[ -n "$pinned_sha" ]] || {'
expect_rejection changed-trusted-workflow \
  '            [[ "$head_policy_blob" == "$default_policy_blob" ]]' \
  '            [[ -n "$head_policy_blob" ]]'
expect_rejection compatibility-job-omitted \
  "          compatibility_job='Debian 11 systemd 247 PID1 VM'" \
  "          compatibility_job='untrusted compatibility result'"

printf 'trusted privileged workflow negative tests passed\n'
