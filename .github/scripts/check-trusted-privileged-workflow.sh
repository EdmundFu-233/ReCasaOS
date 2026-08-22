#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

die() {
  printf 'trusted privileged workflow check failed: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
workflow="${1:-$repo_root/.github/workflows/trusted-privileged-ci.yml}"
primary_workflow="${2:-$repo_root/.github/workflows/recasaos-ci-security.yml}"

[[ -f "$workflow" ]] || die "workflow is missing: $workflow"
[[ -f "$primary_workflow" ]] ||
  die "primary workflow is missing: $primary_workflow"

require_text() {
  local text="$1"
  local reason="$2"
  grep -Fq -- "$text" "$workflow" || die "$reason"
}

forbid_text() {
  local text="$1"
  local reason="$2"
  if grep -Fq -- "$text" "$workflow"; then
    die "$reason"
  fi
}

job_block_from() {
  local workflow_path="$1"
  local job="$2"
  awk -v header="  ${job}:" '
    $0 == header {
      found = 1
      capture = 1
    }
    capture && $0 != header && $0 ~ /^  [A-Za-z0-9_-]+:$/ {
      exit
    }
    capture {
      print
    }
    END {
      if (!found) {
        exit 2
      }
    }
  ' "$workflow_path" || die "job is missing: $job"
}

job_block() {
  job_block_from "$workflow" "$1"
}

require_block_text() {
  local block="$1"
  local text="$2"
  local reason="$3"
  grep -Fq -- "$text" <<<"$block" || die "$reason"
}

forbid_block_text() {
  local block="$1"
  local text="$2"
  local reason="$3"
  if grep -Fq -- "$text" <<<"$block"; then
    die "$reason"
  fi
}

block_text_count() {
  local block="$1"
  local needle="$2"
  local count=0
  local remainder="$block"

  [[ -n "$needle" ]] || die "cannot count an empty policy fragment"
  while [[ "$remainder" == *"$needle"* ]]; do
    remainder="${remainder#*"$needle"}"
    count=$((count + 1))
  done
  printf '%d\n' "$count"
}

require_block_text_count() {
  local block="$1"
  local text="$2"
  local expected="$3"
  local reason="$4"
  local actual

  actual="$(block_text_count "$block" "$text")"
  [[ "$actual" == "$expected" ]] ||
    die "$reason (found $actual, expected $expected)"
}

step_block() {
  local block="$1"
  local step="$2"
  awk -v header="      - name: ${step}" '
    $0 == header {
      found = 1
      capture = 1
    }
    capture && $0 != header && $0 ~ /^      - name:/ {
      exit
    }
    capture {
      print
    }
    END {
      if (!found) {
        exit 2
      }
    }
  ' <<<"$block" || die "step is missing: $step"
}

require_text 'name: Trusted privileged exact-SHA' \
  "workflow name changed"
require_text '  workflow_run:' "workflow_run trigger is missing"
require_text '  repository_dispatch:' "manual promotion trigger is missing"
require_text '      - trusted-privileged-promote' \
  "manual promotion event type changed"
require_text '      - ReCasaOS CI and security' \
  "automatic attestation is not bound to the primary workflow"
require_text '  STATUS_CONTEXT: ReCasaOS / trusted privileged exact-SHA' \
  "required status context changed"
require_text '  cancel-in-progress: false' \
  "same-SHA promotion runs must not cancel one another"

forbid_text 'pull_request_target' \
  "pull_request_target must never enter the trusted workflow"
forbid_text 'workflow_dispatch:' \
  "manual promotion must not accept a caller-selected workflow ref"
forbid_text 'secrets:' "the trusted workflow must not receive secrets"
forbid_text 'id-token: write' "OIDC write permission is forbidden"
forbid_text 'actions/cache' "shared caches are forbidden"
forbid_text 'cache: true' "setup action caches are forbidden"
forbid_text 'persist-credentials: true' \
  "checkout credentials must never persist"
forbid_text 'download-artifact' "untrusted artifacts must not be consumed"
forbid_text 'upload-artifact' "promotion evidence must remain API-bound"

attest_block="$(job_block attest-trusted-run)"
prepare_block="$(job_block prepare-promotion)"
privileged_block="$(job_block privileged-promotion)"
publish_block="$(job_block publish-promotion)"
cleanup_block="$(job_block cleanup-promotion)"
primary_privileged_block="$(
  job_block_from "$primary_workflow" privileged-mount-tests
)"

primary_compile_step="$(
  step_block "$primary_privileged_block" \
    'Compile privileged test binaries without root'
)"
trusted_compile_step="$(
  step_block "$privileged_block" \
    'Compile all trusted test binaries without root'
)"
management_step_name='Exercise management mount-boundary regressions'
primary_management_step="$(
  step_block "$primary_privileged_block" "$management_step_name"
)"
trusted_management_step="$(
  step_block "$privileged_block" "$management_step_name"
)"

# These comparisons freeze the reviewed YAML step templates. They deliberately
# do not claim to parse or prove the semantics of arbitrary shell source.
expected_primary_compile_step="$(cat <<'EOF'
      - name: Compile privileged test binaries without root
        timeout-minutes: 5
        shell: bash
        run: |
          umask 022
          CGO_ENABLED=0 go test -c \
            -o "$RUNNER_TEMP/recasaos-filesecurity.test" \
            ./pkg/filesecurity
          CGO_ENABLED=0 go test -c \
            -o "$RUNNER_TEMP/recasaos-publicfiles.test" \
            ./pkg/publicfiles
          test -x "$RUNNER_TEMP/recasaos-filesecurity.test"
          test -x "$RUNNER_TEMP/recasaos-publicfiles.test"
EOF
)"
expected_trusted_compile_step="$(cat <<'EOF'
      - name: Compile all trusted test binaries without root
        timeout-minutes: 5
        shell: bash
        env:
          EXPECTED_SHA: ${{ needs.prepare-promotion.outputs.head_sha }}
          EXPECTED_TREE: ${{ needs.prepare-promotion.outputs.tree_sha }}
        run: |
          set -Eeuo pipefail
          IFS=$'\n\t'
          umask 022
          CGO_ENABLED=0 go test -c \
            -o "$RUNNER_TEMP/recasaos-samba.test" \
            ./pkg/samba
          CGO_ENABLED=0 go test -c \
            -o "$RUNNER_TEMP/recasaos-sqlite.test" \
            ./pkg/sqlite
          CGO_ENABLED=0 go test -c \
            -o "$RUNNER_TEMP/recasaos-filesecurity.test" \
            ./pkg/filesecurity
          CGO_ENABLED=0 go test -c \
            -o "$RUNNER_TEMP/recasaos-publicfiles.test" \
            ./pkg/publicfiles
          for test_binary in \
            "$RUNNER_TEMP/recasaos-samba.test" \
            "$RUNNER_TEMP/recasaos-sqlite.test" \
            "$RUNNER_TEMP/recasaos-filesecurity.test" \
            "$RUNNER_TEMP/recasaos-publicfiles.test"
          do
            test -x "$test_binary"
          done
          [[ "$(git rev-parse HEAD)" == "$EXPECTED_SHA" ]]
          [[ "$(git show -s --format=%T HEAD)" == "$EXPECTED_TREE" ]]
          [[ -z "$(git status --short)" ]]
EOF
)"
expected_primary_management_step="$(cat <<'EOF'
      - name: Exercise management mount-boundary regressions
        timeout-minutes: 5
        shell: bash
        run: |
          required_management_tests=(
            TestManagedDirectDirectoryRenameRejectsNestedBindMount
            TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling
            TestManagedRootsTreeSizeRejectsNestedBindMount
            TestManagedDirectoryCopyRejectsBindMountAliasIntoSource
            TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot
            TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot
            TestWalkManagedArchiveRejectsChildMountReplacement
            TestWalkManagedArchiveAllowsStableNestedMount
          )
          for required_test in "${required_management_tests[@]}"; do
            listed="$(
              "$RUNNER_TEMP/recasaos-filesecurity.test" \
                -test.list "^${required_test}$"
            )"
            if [[ "$listed" != "$required_test" ]]; then
              printf 'required privileged test is missing: %s\n' \
                "$required_test" >&2
              exit 1
            fi
          done
          sudo unshare --mount --propagation private --fork --kill-child=KILL \
            env \
              PATH=/usr/sbin:/usr/bin:/sbin:/bin \
              RECASAOS_PRIVILEGED_MOUNT_TEST=1 \
              "$RUNNER_TEMP/recasaos-filesecurity.test" \
                -test.count=1 \
                -test.run '^(TestManagedDirectDirectoryRenameRejectsNestedBindMount|TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling|TestManagedRootsTreeSizeRejectsNestedBindMount|TestManagedDirectoryCopyRejectsBindMountAliasIntoSource|TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot|TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot|TestWalkManagedArchiveRejectsChildMountReplacement|TestWalkManagedArchiveAllowsStableNestedMount)$' \
                -test.timeout=4m \
                -test.v
EOF
)"
expected_trusted_management_step="$(cat <<'EOF'
      - name: Exercise management mount-boundary regressions
        timeout-minutes: 5
        shell: bash
        run: |
          set -Eeuo pipefail
          IFS=$'\n\t'
          required_management_tests=(
            TestManagedDirectDirectoryRenameRejectsNestedBindMount
            TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling
            TestManagedRootsTreeSizeRejectsNestedBindMount
            TestManagedDirectoryCopyRejectsBindMountAliasIntoSource
            TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot
            TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot
            TestWalkManagedArchiveRejectsChildMountReplacement
            TestWalkManagedArchiveAllowsStableNestedMount
          )
          for required_test in "${required_management_tests[@]}"; do
            listed="$(
              "$RUNNER_TEMP/recasaos-filesecurity.test" \
                -test.list "^${required_test}$"
            )"
            if [[ "$listed" != "$required_test" ]]; then
              printf 'required privileged test is missing: %s\n' \
                "$required_test" >&2
              exit 1
            fi
          done
          sudo unshare --mount --propagation private --fork --kill-child=KILL \
            env \
              PATH=/usr/sbin:/usr/bin:/sbin:/bin \
              RECASAOS_PRIVILEGED_MOUNT_TEST=1 \
              "$RUNNER_TEMP/recasaos-filesecurity.test" \
                -test.count=1 \
                -test.run '^(TestManagedDirectDirectoryRenameRejectsNestedBindMount|TestManagedRemoveAllPreflightsNestedMountBeforeDeletingSibling|TestManagedRootsTreeSizeRejectsNestedBindMount|TestManagedDirectoryCopyRejectsBindMountAliasIntoSource|TestManagedRegularCopyRejectsDestinationBindAliasIntoAnotherConfiguredRoot|TestManagedReplaceCleanupRejectsBindAliasAncestorOfConfiguredRoot|TestWalkManagedArchiveRejectsChildMountReplacement|TestWalkManagedArchiveAllowsStableNestedMount)$' \
                -test.timeout=4m \
                -test.v
EOF
)"

[[ "$primary_compile_step" == "$expected_primary_compile_step" ]] ||
  die "primary privileged compile step drifted"
[[ "$trusted_compile_step" == "$expected_trusted_compile_step" ]] ||
  die "trusted privileged compile step drifted"
[[ "$primary_management_step" == "$expected_primary_management_step" ]] ||
  die "primary management step drifted from the exact executable template"
[[ "$trusted_management_step" == "$expected_trusted_management_step" ]] ||
  die "trusted management step drifted from the exact executable template"
require_block_text_count "$primary_privileged_block" \
  'recasaos-filesecurity.test' 4 \
  "primary privileged job contains an extra filesecurity binary reference"
require_block_text_count "$privileged_block" \
  'recasaos-filesecurity.test' 4 \
  "trusted privileged job contains an extra filesecurity binary reference"

for block_name in attest prepare publish cleanup; do
  case "$block_name" in
    attest) block="$attest_block" ;;
    prepare) block="$prepare_block" ;;
    publish) block="$publish_block" ;;
    cleanup) block="$cleanup_block" ;;
  esac
  forbid_block_text "$block" '      - uses:' \
    "$block_name write-capable/API job must not invoke external actions"
done

require_block_text "$attest_block" '      statuses: write' \
  "automatic attestor cannot publish commit status"
require_block_text "$attest_block" \
  '[[ "$head_policy_blob" == "$default_policy_blob" ]]' \
  "automatic attestor does not pin trusted policy blobs"
for trusted_path in \
  .github/workflows/recasaos-ci-security.yml \
  .github/workflows/trusted-privileged-ci.yml \
  .github/scripts/check-debian11-systemd-vm-policy.sh \
  .github/scripts/check-trusted-privileged-workflow.sh \
  .github/scripts/sample-cgroup-memory.py \
  .github/scripts/test-cgroup-memory-sampler.sh \
  .github/scripts/test-debian11-systemd-vm-policy.sh \
  .github/scripts/test-public-files-debian11-vm.sh \
  .github/scripts/test-public-files-systemd.sh \
  .github/scripts/test-trusted-privileged-workflow.sh
do
  require_block_text "$attest_block" "$trusted_path" \
    "automatic attestor does not freeze policy file: $trusted_path"
done
require_block_text "$attest_block" \
  '"repos/$REPOSITORY/commits/$RUN_HEAD_SHA/pulls"' \
  "automatic attestor does not resolve PRs through the immutable run head"
require_block_text "$attest_block" \
  '.head.sha == $head_sha' \
  "automatic PR association is not bound to the exact run head"
require_block_text "$attest_block" \
  '[[ "$current_head" == "$RUN_HEAD_SHA" ]]' \
  "automatic attestor does not re-read the current PR head"
require_block_text "$attest_block" \
  "privileged_job='Privileged mount regressions (isolated namespace)'" \
  "automatic attestor does not require the privileged mount job"
require_block_text "$attest_block" \
  "compatibility_job='Debian 11 systemd 247 PID1 VM'" \
  "automatic attestor does not require the Debian 11 PID1 VM job"
require_block_text "$attest_block" \
  'skip "Debian 11 PID1 VM job did not pass exactly once"' \
  "automatic attestor does not enforce the Debian 11 PID1 VM result"
require_block_text "$attest_block" \
  "'Verify isolated Samba probe privilege boundary'" \
  "automatic attestor omits the trusted Samba step"
require_block_text "$attest_block" \
  "'Verify SQLite sticky-directory ownership boundary'" \
  "automatic attestor omits the trusted SQLite step"
require_block_text "$attest_block" \
  '"repos/$REPOSITORY/statuses/$RUN_HEAD_SHA"' \
  "automatic status is not bound to the run head SHA"

require_block_text "$prepare_block" '      contents: write' \
  "manual preparation cannot create the trusted ref"
require_block_text "$prepare_block" '      statuses: write' \
  "manual preparation cannot publish pending evidence"
require_block_text "$prepare_block" \
  "github.event_name == 'repository_dispatch'" \
  "manual promotion is not bound to repository_dispatch"
require_block_text "$prepare_block" \
  "github.event.action == 'trusted-privileged-promote'" \
  "manual promotion does not require the exact event type"
require_block_text "$prepare_block" \
  "github.ref == format('refs/heads/{0}', github.event.repository.default_branch)" \
  "manual promotion is not restricted to the default workflow ref"
require_block_text "$prepare_block" \
  'PR_NUMBER: ${{ github.event.client_payload.pull_request }}' \
  "manual promotion does not read the repository event PR number"
require_block_text "$prepare_block" \
  'EXPECTED_SHA: ${{ github.event.client_payload.head_sha }}' \
  "manual promotion does not read the repository event head SHA"
require_block_text "$prepare_block" \
  '[[ "$EXPECTED_SHA" =~ ^[0-9a-f]{40}$ ]]' \
  "manual promotion does not validate the complete lowercase SHA"
require_block_text "$prepare_block" \
  '[[ "$(jq -r '\''.head.sha'\'' <<<"$pr_json")" == "$EXPECTED_SHA" ]]' \
  "manual promotion does not compare the live PR head"
require_block_text "$prepare_block" \
  'trusted_ref="refs/heads/ci/trusted-pr-${PR_NUMBER}-${EXPECTED_SHA}"' \
  "trusted ref is not namespaced by PR and full SHA"
require_block_text "$prepare_block" \
  'git/matching-refs/heads/$trusted_branch' \
  "trusted ref lookup cannot distinguish absence from an API failure"
require_block_text "$prepare_block" \
  '[[ "$pinned_sha" == "$EXPECTED_SHA" ]]' \
  "trusted ref identity is not read back"
require_block_text "$prepare_block" \
  'git/commits/$EXPECTED_SHA' \
  "tree identity is not obtained from the exact commit"
require_block_text "$prepare_block" '-f state=pending' \
  "manual promotion does not publish a pending exact-SHA status"

require_block_text "$privileged_block" '      contents: read' \
  "untrusted code runner does not have read-only contents permission"
require_block_text "$privileged_block" \
  'uses: actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd' \
  "checkout is not pinned to the reviewed action commit"
require_block_text "$privileged_block" \
  'ref: ${{ needs.prepare-promotion.outputs.trusted_branch }}' \
  "untrusted code runner does not check out the pinned same-repository ref"
require_block_text "$privileged_block" 'persist-credentials: false' \
  "untrusted code runner persists checkout credentials"
require_block_text "$privileged_block" 'cache: false' \
  "untrusted code runner enables a shared setup-go cache"
require_block_text "$privileged_block" \
  '[[ "$actual_sha" == "$EXPECTED_SHA" ]]' \
  "runner does not verify commit identity"
require_block_text "$privileged_block" \
  '[[ "$actual_tree" == "$EXPECTED_TREE" ]]' \
  "runner does not verify tree identity"
for trusted_binary in \
  'recasaos-samba.test' \
  'recasaos-sqlite.test' \
  'recasaos-filesecurity.test' \
  'recasaos-publicfiles.test'
do
  require_block_text "$privileged_block" "$trusted_binary" \
    "trusted binary is not compiled before root execution: $trusted_binary"
done
require_block_text "$privileged_block" \
  '[[ -z "$(git status --short)" ]]' \
  "runner does not revalidate the clean exact tree after compilation"
require_block_text "$privileged_block" \
  'sudo unshare --mount --propagation private --fork --kill-child=KILL' \
  "privileged matrix lost its private mount namespace"
require_block_text "$privileged_block" \
  '^(TestPublicVerifierBindAliasDisclosureCannotAuthenticate|TestPinnedPublicRootSurvivesBindMountReplacement|TestPublicRootRejectsNestedBindMount|TestPublicRootAcceptsTmpfsInIsolatedNamespace|TestPublicRootAllowlistedFilesystemCompatibilityMatrix)$' \
  "public-root mount regression matrix drifted"
require_block_text "$privileged_block" \
  '^TestRealProbeSandboxDropsIdentityAndAppliesLimitsBeforeReady$' \
  "trusted Samba boundary test is missing"
require_block_text "$privileged_block" \
  '^TestPrepareSecureDatabaseDirectoryRejectsForeignOwnedChildInStickyAncestor$' \
  "trusted SQLite boundary test is missing"
forbid_block_text "$privileged_block" 'GH_TOKEN:' \
  "untrusted code runner receives GH_TOKEN"
forbid_block_text "$privileged_block" '${{ github.token }}' \
  "untrusted code runner receives the workflow token expression"
forbid_block_text "$privileged_block" 'contents: write' \
  "untrusted code runner has contents write permission"
forbid_block_text "$privileged_block" 'statuses: write' \
  "untrusted code runner has status write permission"

require_block_text "$publish_block" '      statuses: write' \
  "manual publisher cannot publish exact-SHA evidence"
require_block_text "$publish_block" \
  '[[ "$pinned_sha" == "$EXPECTED_SHA" ]]' \
  "publisher does not revalidate the trusted ref"
require_block_text "$publish_block" \
  '[[ "$actual_tree" == "$EXPECTED_TREE" ]]' \
  "publisher does not revalidate tree identity"
require_block_text "$publish_block" \
  '[[ "$VERIFIED_SHA" == "$EXPECTED_SHA" ]]' \
  "publisher does not require runner commit evidence"
require_block_text "$publish_block" \
  '[[ "$VERIFIED_TREE" == "$EXPECTED_TREE" ]]' \
  "publisher does not require runner tree evidence"
require_block_text "$publish_block" \
  '"repos/$REPOSITORY/statuses/$EXPECTED_SHA"' \
  "manual status is not bound to the exact SHA"

require_block_text "$cleanup_block" '      contents: write' \
  "cleanup cannot remove the one-time trusted ref"
require_block_text "$cleanup_block" \
  "github.event.action == 'trusted-privileged-promote'" \
  "cleanup is not bound to the exact repository event type"
require_block_text "$cleanup_block" \
  'trusted_branch="ci/trusted-pr-${PR_NUMBER}-${EXPECTED_SHA}"' \
  "cleanup does not derive the exact trusted ref"
require_block_text "$cleanup_block" \
  'git/matching-refs/heads/$trusted_branch' \
  "cleanup cannot distinguish absence from an API failure"
require_block_text "$cleanup_block" \
  '[[ "$pinned_sha" == "$EXPECTED_SHA" ]]' \
  "cleanup may delete a ref after it moved"
require_block_text "$cleanup_block" \
  'git/refs/heads/$trusted_branch' \
  "cleanup does not delete only the derived branch ref"

printf 'trusted privileged workflow check passed\n'
