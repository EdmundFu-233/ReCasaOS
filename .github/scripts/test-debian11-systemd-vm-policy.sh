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
hostile_worker_lifecycle_test="$script_directory/test-hostile-worker-exe-lifecycle.py"
workflow="$repository/.github/workflows/recasaos-ci-security.yml"
vm_script="$repository/.github/scripts/test-public-files-debian11-vm.sh"
systemd_script="$repository/.github/scripts/test-public-files-systemd.sh"
sampler="$repository/.github/scripts/sample-cgroup-memory.py"

[[ -x "$checker" ]] || fail "policy checker is not executable"
command -v perl >/dev/null 2>&1 || fail "perl is unavailable"
command -v python3 >/dev/null 2>&1 || fail "Python is unavailable"
[[ -f "$hostile_worker_lifecycle_test" ]] ||
  fail "hostile-worker executable lifecycle test is unavailable"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-debian-vm-policy.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

"$checker" "$workflow" "$vm_script" "$systemd_script" "$sampler"
python3 "$hostile_worker_lifecycle_test" "$systemd_script"

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
expect_rejection hostile-storage-opt-in vm \
  '      RECASAOS_HOSTILE_STORAGE_VM_CI=1 \' \
  '      RECASAOS_HOSTILE_STORAGE_VM_CI=0 \'
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
expect_rejection incomplete-bounded-worker-inspection systemd \
  '    or len(worker_pairs) != 8' \
  '    or len(worker_pairs) != 1'
expect_rejection skipped-bounded-worker-inspection systemd \
  $'\nassert_bounded_storage_worker_runtime_boundaries\nstop_cgroup_memory_sampler' \
  $'\n: # bounded worker inspection skipped\nstop_cgroup_memory_sampler'
expect_rejection inherited-listener-inspection systemd \
  '        if os.readlink(descriptor_path) == listener_target:' \
  '        if os.readlink(descriptor_path) != listener_target:'
expect_rejection memory-peak-fail-open systemd \
  'elif [[ "${RECASAOS_SYSTEMD_TEST_TARGET:-}" != \' \
  'elif [[ -z "${RECASAOS_SYSTEMD_TEST_TARGET:-}" && \'
expect_rejection host-hostile-storage-enable systemd \
  '    hostile_storage_test_enabled=0' \
  '    hostile_storage_test_enabled=1'
expect_rejection hostile-storage-flushing-suspend systemd \
  'sudo dmsetup suspend --nolockfs --noflush "$hostile_storage_name"' \
  'sudo dmsetup suspend "$hostile_storage_name"'
expect_rejection hostile-storage-fake-state systemd \
  'if task_state == b"D":' \
  'if task_state == b"T":'
expect_rejection hostile-storage-short-formation-window systemd \
  'hostile_blocked_deadline=$((SECONDS + 8))' \
  'hostile_blocked_deadline=$((SECONDS + 7))'
expect_rejection hostile-storage-expanded-formation-window systemd \
  'hostile_blocked_deadline=$((SECONDS + 8))' \
  'hostile_blocked_deadline=$((SECONDS + 9))'
expect_rejection hostile-storage-deadline-after-clients systemd \
  $'  hostile_blocked_deadline=$((SECONDS + 8))\n  for _ in {1..4}; do\n    start_hostile_storage_client\n  done' \
  $'  ignored_deadline=$((SECONDS + 8))\n  for _ in {1..4}; do\n    start_hostile_storage_client\n  done\n  hostile_blocked_deadline=$((SECONDS + 8))'
expect_rejection hostile-storage-unbound-cgroup-task systemd \
  '        if thread_status.get(b"Tgid") != str(pid).encode("ascii"):' \
  '        if False:'
expect_rejection hostile-storage-three-d-state-workers systemd \
  'storage_workers_are_in_d_state 4' \
  'storage_workers_are_in_d_state 3'
expect_rejection hostile-storage-split-formation-deadline systemd \
  '    "$hostile_blocked_deadline" \' \
  '    "$hostile_timeout_deadline" \'
expect_rejection hostile-storage-blocked-allows-pending-kill systemd \
  'if phase == "blocked" and kill_is_pending:' \
  'if phase == "blocked" and false:'
expect_rejection hostile-storage-empty-worker-set systemd \
  'seen = set()' \
  $'worker_pairs = ()\nseen = set()'
expect_rejection hostile-storage-skipped-worker-inspection systemd \
  '    state, parent, start_before = read_identity(pid)' \
  $'    continue\n    state, parent, start_before = read_identity(pid)'
expect_rejection hostile-storage-inspection-early-return systemd \
  $'assert_hostile_storage_worker_boundaries() {\n  local expected_parent=$2' \
  $'assert_hostile_storage_worker_boundaries() {\n  return 0\n  local expected_parent=$2'
expect_rejection hostile-storage-inspection-override systemd \
  'hostile_storage_clients_are_live() {' \
  $'assert_hostile_storage_worker_boundaries() { :; }\n\nhostile_storage_clients_are_live() {'
expect_rejection hostile-storage-missing-exe-in-blocked-phase systemd \
  '        phase == "kill-pending"' \
  '        phase in {"blocked", "kill-pending"}'
expect_rejection hostile-storage-missing-exe-non-zombie systemd \
  '        and state == b"Z"' \
  '        and state in {b"D", b"Z"}'
expect_rejection hostile-storage-missing-exe-unpinned-parent systemd \
  '        and parent == expected_parent' \
  '        and parent >= 1'
expect_rejection hostile-storage-missing-exe-unpinned-start systemd \
  '        and start == expected_start' \
  '        and start.isdigit()'
expect_rejection hostile-storage-missing-exe-leader-task systemd \
  '        and d_tid != pid' \
  '        and d_tid == pid'
expect_rejection hostile-storage-missing-exe-catch-all systemd \
  '    except FileNotFoundError as error:' \
  '    except OSError as error:'
expect_rejection hostile-storage-missing-exe-no-survivor-image systemd \
  '        worker_executable = os.stat(proc_root / str(d_tid) / "exe")' \
  '        worker_executable = reviewed_binary'
expect_rejection hostile-storage-missing-exe-leader-status systemd \
  '        status_pid = d_tid' \
  '        status_pid = pid'
expect_rejection hostile-storage-missing-exe-unpinned-tgid systemd \
  '    if status.get(b"Tgid") != str(pid).encode("ascii"):' \
  '    if False:'
expect_rejection hostile-storage-missing-exe-unpinned-status-pid systemd \
  '    if status.get(b"Pid") != str(status_pid).encode("ascii"):' \
  '    if False:'
expect_rejection hostile-storage-missing-exe-no-final-zombie-check systemd \
  '    if leader_executable_missing and state_after != b"Z":' \
  '    if False:'
expect_rejection hostile-storage-missing-final-cgroup-membership systemd \
  '    if d_tid not in read_cgroup_tids():' \
  '    if False:'
expect_rejection hostile-storage-incomplete-inspection systemd \
  'or len(worker_pairs) != 4' \
  'or len(worker_pairs) != 1'
expect_rejection hostile-storage-missing-pid1-reparent systemd \
  'assert_hostile_storage_worker_boundaries kill-pending 1' \
  'assert_hostile_storage_worker_boundaries kill-pending "$portal_pid"'
expect_rejection hostile-storage-missing-post-inspection-client-check systemd \
  $'  hostile_storage_clients_are_live ||\n    fail "hostile-storage clients exited during blocked worker inspection"' \
  '  : # blocked client liveness recheck skipped'
expect_rejection hostile-storage-cleanup-without-resume systemd \
  'if ! resume_hostile_storage_for_cleanup; then' \
  'if false; then'
expect_rejection sampler-symlink-follow sampler \
  'source_flags |= os.O_NOFOLLOW' \
  'source_flags |= 0'

printf 'Debian 11 systemd VM policy negative tests passed\n'
