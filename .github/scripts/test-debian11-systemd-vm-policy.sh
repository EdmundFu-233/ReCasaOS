#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Debian 11 systemd VM policy negative tests failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
checker="$script_directory/check-debian11-systemd-vm-policy.sh"
workflow="$repository/.github/workflows/recasaos-ci-security.yml"
vm_script="$repository/.github/scripts/test-public-files-debian11-vm.sh"
systemd_script="$repository/.github/scripts/test-public-files-systemd.sh"
sampler="$repository/.github/scripts/sample-cgroup-memory.py"

[[ -x "$checker" ]] || fail "policy checker is not executable"
command -v perl >/dev/null 2>&1 || fail "perl is unavailable"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-debian-vm-policy.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

"$checker" "$workflow" "$vm_script" "$systemd_script" "$sampler"

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
  local target=$2
  local needle=$3
  local replacement=$4
  local candidate_directory="$workspace/$label"
  local candidate_workflow="$candidate_directory/workflow.yml"
  local candidate_vm="$candidate_directory/vm.sh"
  local candidate_systemd="$candidate_directory/systemd.sh"
  local candidate_sampler="$candidate_directory/sampler.py"
  local mutation_file

  mkdir "$candidate_directory"
  cp -- "$workflow" "$candidate_workflow"
  cp -- "$vm_script" "$candidate_vm"
  cp -- "$systemd_script" "$candidate_systemd"
  cp -- "$sampler" "$candidate_sampler"
  case "$target" in
    workflow) mutation_file=$candidate_workflow ;;
    vm) mutation_file=$candidate_vm ;;
    systemd) mutation_file=$candidate_systemd ;;
    sampler) mutation_file=$candidate_sampler ;;
    *) fail "unknown mutation target: $target" ;;
  esac
  replace_once "$mutation_file" "$needle" "$replacement"
  if "$checker" \
    "$candidate_workflow" \
    "$candidate_vm" \
    "$candidate_systemd" \
    "$candidate_sampler" \
    >"$candidate_directory/result.log" 2>&1; then
    fail "unsafe mutation was accepted: $label"
  fi
}

expect_rejection stale-checkout workflow \
  'ref: ${{ github.event.pull_request.head.sha || github.sha }}' \
  'ref: ${{ github.sha }}'
expect_rejection shared-cache workflow \
  '          cache: false' \
  '          cache: true'
expect_rejection fork-access workflow \
  $'  debian11-systemd247-pid1:\n    name: Debian 11 systemd 247 PID1 VM\n    if: >-\n      github.event_name !=' \
  $'  debian11-systemd247-pid1:\n    name: Debian 11 systemd 247 PID1 VM\n    if: >-\n      github.event_name =='
expect_rejection checksum-drift vm \
  '67dcf10dc67b807596c21b36fcd0a752838c124420774737d4badc46cb115b88cc879fac91a22d149d74b2ecd9600a7b4761690900348726e718f501a8564131' \
  '07dcf10dc67b807596c21b36fcd0a752838c124420774737d4badc46cb115b88cc879fac91a22d149d74b2ecd9600a7b4761690900348726e718f501a8564131'
expect_rejection hardware-acceleration vm \
  '-accel tcg,thread=multi' \
  '-enable-kvm'
expect_rejection stale-sha vm \
  '[[ "$actual_sha" == "$RECASAOS_EXPECTED_SHA" ]]' \
  '[[ -n "$actual_sha" ]]'
expect_rejection debian-noexec-workspace systemd \
  '    workspace_parent=/var/lib' \
  '    workspace_parent=/run'
expect_rejection expanded-tcg-capacity-window systemd \
  '    worker_capacity_window_seconds=30' \
  '    worker_capacity_window_seconds=60'
expect_rejection expanded-capacity-evidence-window systemd \
  'worker_capacity_evidence_window_seconds=10' \
  'worker_capacity_evidence_window_seconds=20'
expect_rejection serialized-capacity-admission systemd \
  'for _ in {1..8}; do' \
  'for expected_worker_count in {1..8}; do'
expect_rejection memory-peak-fail-open systemd \
  'elif [[ "${RECASAOS_SYSTEMD_TEST_TARGET:-}" != \' \
  'elif [[ -z "${RECASAOS_SYSTEMD_TEST_TARGET:-}" && \'
expect_rejection sampler-symlink-follow sampler \
  'source_flags |= os.O_NOFOLLOW' \
  'source_flags |= 0'

printf 'Debian 11 systemd VM policy negative tests passed\n'
