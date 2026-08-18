#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Go toolchain version policy negative tests failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
checker="$script_directory/check-go-toolchain-version.sh"
[[ -x "$checker" ]] || fail 'policy checker is not executable'
command -v perl >/dev/null 2>&1 || fail 'perl is unavailable'

workspace="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-go-toolchain-policy.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

copy_policy_tree() {
  local destination=$1

  mkdir -p "$destination/.github/workflows" "$destination/.github/scripts"
  cp -- "$repository/go.mod" "$destination/go.mod"
  cp -- "$repository/.github/workflows/codeql.yml" \
    "$destination/.github/workflows/codeql.yml"
  cp -- "$repository/.github/workflows/recasaos-ci-security.yml" \
    "$destination/.github/workflows/recasaos-ci-security.yml"
  cp -- "$repository/.github/workflows/trusted-privileged-ci.yml" \
    "$destination/.github/workflows/trusted-privileged-ci.yml"
  cp -- "$repository/.github/scripts/test-public-files-debian11-vm.sh" \
    "$destination/.github/scripts/test-public-files-debian11-vm.sh"
  cp -- "$repository/.github/scripts/test-public-files-systemd.sh" \
    "$destination/.github/scripts/test-public-files-systemd.sh"
}

replace_once() {
  local file=$1
  local needle=$2
  local replacement=$3

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
  local label=$1
  local relative_file=$2
  local needle=$3
  local replacement=$4
  local expected_reason=$5
  local candidate="$workspace/$label"

  copy_policy_tree "$candidate"
  replace_once "$candidate/$relative_file" "$needle" "$replacement"
  if "$checker" "$candidate" >"$candidate/result.log" 2>&1; then
    fail "unsafe mutation was accepted: $label"
  fi
  grep -Fq -- "$expected_reason" "$candidate/result.log" ||
    fail "unsafe mutation was rejected for the wrong reason: $label"
}

expect_pairing_rejection() {
  local label=$1
  local relative_file=$2
  local first_needle=$3
  local first_replacement=$4
  local second_needle=$5
  local second_replacement=$6
  local expected_reason=$7
  local candidate="$workspace/$label"

  copy_policy_tree "$candidate"
  replace_once "$candidate/$relative_file" \
    "$first_needle" "$first_replacement"
  replace_once "$candidate/$relative_file" \
    "$second_needle" "$second_replacement"
  if "$checker" "$candidate" >"$candidate/result.log" 2>&1; then
    fail "unsafe pairing mutation was accepted: $label"
  fi
  grep -Fq -- "$expected_reason" "$candidate/result.log" ||
    fail "unsafe pairing mutation was rejected for the wrong reason: $label"
}

"$checker" "$repository"
directory_candidate="$workspace/scripts-directory"
copy_policy_tree "$directory_candidate"
mkdir "$directory_candidate/.github/scripts/testdata"
"$checker" "$directory_candidate" >/dev/null ||
  fail 'an ordinary scripts subdirectory was rejected'
non_go_candidate="$workspace/non-go-workflow"
copy_policy_tree "$non_go_candidate"
printf '%s\n' \
  'name: Documentation' \
  'on: workflow_dispatch' \
  'jobs:' \
  '  docs:' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - run: echo docs' \
  >"$non_go_candidate/.github/workflows/docs.yml"
"$checker" "$non_go_candidate" >/dev/null ||
  fail 'a workflow without Go configuration was rejected'
partial_go_candidate="$workspace/partial-go-workflow"
copy_policy_tree "$partial_go_candidate"
printf '%s\n' \
  'name: Partial Go policy' \
  'on: workflow_dispatch' \
  'env:' \
  '  GOTOOLCHAIN: local' \
  'jobs:' \
  '  partial:' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - run: go version' \
  >"$partial_go_candidate/.github/workflows/partial.yml"
if "$checker" "$partial_go_candidate" \
  >"$partial_go_candidate/result.log" 2>&1; then
  fail 'a partial Go workflow policy was accepted'
fi
grep -Fq -- 'partial Go toolchain policy exists without setup-go' \
  "$partial_go_candidate/result.log" ||
  fail 'partial Go workflow was rejected for the wrong reason'
inline_go_candidate="$workspace/inline-go-workflow"
copy_policy_tree "$inline_go_candidate"
printf '%s\n' \
  'name: Inline Go override' \
  'on: workflow_dispatch' \
  'jobs:' \
  '  inline:' \
  '    runs-on: ubuntu-24.04' \
  '    steps:' \
  '      - run: GOTOOLCHAIN=go1.26.5 go test ./...' \
  >"$inline_go_candidate/.github/workflows/inline.yml"
if "$checker" "$inline_go_candidate" \
  >"$inline_go_candidate/result.log" 2>&1; then
  fail 'an inline Go override without setup-go was accepted'
fi
grep -Fq -- 'inline GOTOOLCHAIN override is forbidden' \
  "$inline_go_candidate/result.log" ||
  fail 'inline Go workflow was rejected for the wrong reason'

expect_rejection stale-go-mod go.mod \
  'toolchain go1.26.6' \
  'toolchain go1.26.5' \
  'go.mod must pin exactly one toolchain'
expect_rejection stale-language-version go.mod \
  'go 1.25.0' \
  'go 1.24.0' \
  'go.mod must pin exactly one language version'
expect_rejection stale-workflow-version \
  .github/workflows/recasaos-ci-security.yml \
  '          go-version: "1.26.6"' \
  '          go-version: "1.26.5"' \
  'setup-go step must pin exactly go-version'
expect_rejection unpinned-workflow-version \
  .github/workflows/codeql.yml \
  '          go-version: "1.26.6"' \
  '          go-version-file: go.mod' \
  'setup-go must not use go-version-file'
expect_rejection stale-workflow-label \
  .github/workflows/trusted-privileged-ci.yml \
  'name: Set up Go 1.26.6' \
  'name: Set up Go 1.26.5' \
  'setup-go step name must start with'
expect_rejection unpinned-setup-action \
  .github/workflows/codeql.yml \
  'uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c' \
  'uses: actions/setup-go@v6' \
  'setup-go action does not use the reviewed SHA'
expect_rejection wrong-setup-action-sha \
  .github/workflows/codeql.yml \
  'uses: actions/setup-go@4a3601121dd01d1626a1e23e37211e3254c1c06c' \
  'uses: actions/setup-go@0000000000000000000000000000000000000000' \
  'setup-go action does not use the reviewed SHA'
expect_rejection version-outside-with \
  .github/workflows/codeql.yml \
  $'        with:\n          go-version: "1.26.6"\n          cache: true' \
  $'        env:\n          go-version: "1.26.6"\n        with:\n          cache: true' \
  'setup-go step must pin exactly go-version'
expect_rejection workflow-toolchain-override \
  .github/workflows/recasaos-ci-security.yml \
  '  GOTOOLCHAIN: local' \
  '  GOTOOLCHAIN: go1.26.5' \
  'inline GOTOOLCHAIN override is forbidden'
expect_rejection shell-toolchain-override \
  .github/workflows/recasaos-ci-security.yml \
  '        run: go test ./...' \
  '        run: export GOTOOLCHAIN=go1.26.5; go test ./...' \
  'inline GOTOOLCHAIN override is forbidden'
expect_rejection orphan-workflow-version \
  .github/workflows/codeql.yml \
  '          persist-credentials: false' \
  $'          persist-credentials: false\n          go-version: "1.26.6"' \
  'orphan go-version key is forbidden'
expect_pairing_rejection workflow-version-filler \
  .github/workflows/codeql.yml \
  '          go-version: "1.26.6"' \
  '          go-version: "1.26.5"' \
  '          persist-credentials: false' \
  $'          persist-credentials: false\n          go-version: "1.26.6"' \
  'setup-go step must pin exactly go-version'
expect_pairing_rejection workflow-name-filler \
  .github/workflows/codeql.yml \
  '      - name: Set up Go 1.26.6' \
  '      - name: Set up Go 1.26.5' \
  '      - name: Check out source' \
  '      - name: Set up Go 1.26.6 filler' \
  'setup-go step name must start with'
expect_rejection stale-hosted-toolcache \
  .github/scripts/test-public-files-debian11-vm.sh \
  '/opt/hostedtoolcache/go/1.26.6/*' \
  '/opt/hostedtoolcache/go/1.26.5/*' \
  'stale hosted-toolcache Go version found'
expect_rejection stale-systemd-runtime \
  .github/scripts/test-public-files-systemd.sh \
  'go version go1.26.6 linux/amd64' \
  'go version go1.26.5 linux/amd64' \
  'stale or unreviewed Go toolchain pin found'

printf 'Go toolchain version policy negative tests passed\n'
