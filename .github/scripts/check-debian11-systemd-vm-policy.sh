#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Debian 11 systemd VM policy check failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
workflow="${1:-$repository/.github/workflows/recasaos-ci-security.yml}"
vm_script="${2:-$repository/.github/scripts/test-public-files-debian11-vm.sh}"
systemd_script="${3:-$repository/.github/scripts/test-public-files-systemd.sh}"
sampler="${4:-$repository/.github/scripts/sample-cgroup-memory.py}"

for file in "$workflow" "$vm_script" "$systemd_script" "$sampler"; do
  [[ -f "$file" && ! -L "$file" ]] ||
    fail "required policy file is missing or symbolic: $file"
done

require_text() {
  local file=$1
  local value=$2
  local reason=$3

  grep -Fq -- "$value" "$file" || fail "$reason"
}

require_exact_line() {
  local file=$1
  local value=$2
  local reason=$3

  grep -Fxq -- "$value" "$file" || fail "$reason"
}

require_exact_count() {
  local file=$1
  local value=$2
  local expected=$3
  local reason=$4
  local count

  count=$(grep -Fxc -- "$value" "$file" || true)
  [[ "$count" == "$expected" ]] ||
    fail "$reason: found $count, want $expected"
}

forbid_text() {
  local file=$1
  local value=$2
  local reason=$3

  if grep -Fq -- "$value" "$file"; then
    fail "$reason"
  fi
}

job_block() {
  local job=$1

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
  ' "$workflow" || fail "workflow job is missing: $job"
}

require_block_text() {
  local block=$1
  local value=$2
  local reason=$3

  grep -Fq -- "$value" <<<"$block" || fail "$reason"
}

forbid_block_text() {
  local block=$1
  local value=$2
  local reason=$3

  if grep -Fq -- "$value" <<<"$block"; then
    fail "$reason"
  fi
}

vm_job="$(job_block debian11-systemd247-pid1)"
require_block_text "$vm_job" 'name: Debian 11 systemd 247 PID1 VM' \
  "VM job name changed"
require_block_text "$vm_job" "github.event_name != 'pull_request' ||" \
  "default-branch VM runs are not required"
require_block_text "$vm_job" \
  "github.event.pull_request.head.repo.full_name == github.repository" \
  "fork pull requests are not excluded"
for association in OWNER MEMBER COLLABORATOR; do
  require_block_text "$vm_job" \
    "github.event.pull_request.author_association == '$association'" \
    "trusted author association is missing: $association"
done
require_block_text "$vm_job" "github.actor != 'dependabot[bot]'" \
  "Dependabot is not excluded"
require_block_text "$vm_job" \
  'ref: ${{ github.event.pull_request.head.sha || github.sha }}' \
  "checkout is not bound to the exact event head"
require_block_text "$vm_job" 'persist-credentials: false' \
  "checkout credentials may persist"
require_block_text "$vm_job" 'cache: false' \
  "VM job must not use a shared setup-go cache"
require_block_text "$vm_job" 'RECASAOS_DEBIAN11_VM_CI: "1"' \
  "VM job explicit opt-in is missing"
require_block_text "$vm_job" \
  'RECASAOS_EXPECTED_SHA: ${{ github.event.pull_request.head.sha || github.sha }}' \
  "VM script is not given the exact event head"
require_block_text "$vm_job" \
  'RECASAOS_RUNNER_ENVIRONMENT: ${{ runner.environment }}' \
  "hosted-runner identity is not forwarded"
require_block_text "$vm_job" \
  'run: .github/scripts/test-public-files-debian11-vm.sh' \
  "reviewed VM script is not invoked"
for package in cloud-image-utils qemu-system-x86 qemu-utils; do
  require_block_text "$vm_job" "$package" \
    "VM job package is missing: $package"
done
for forbidden in \
  'contents: write' \
  'id-token: write' \
  'secrets:' \
  'actions/cache' \
  'actions/upload-artifact' \
  'actions/download-artifact'
do
  forbid_block_text "$vm_job" "$forbidden" \
    "VM job contains forbidden capability: $forbidden"
done

require_text "$vm_script" \
  "[[ \"\$actual_sha\" == \"\$RECASAOS_EXPECTED_SHA\" ]]" \
  "VM script does not verify the exact checkout SHA"
require_text "$vm_script" \
  'git status --porcelain=v1 --untracked-files=all' \
  "VM script does not require a clean checkout"
require_text "$vm_script" \
  '--output="$repo_archive" "$RECASAOS_EXPECTED_SHA"' \
  "guest source archive is not bound to the exact SHA"
require_text "$vm_script" \
  "image_url='https://cloud.debian.org/images/cloud/bullseye/20260728-2553/debian-11-generic-amd64-20260728-2553.qcow2'" \
  "Debian cloud image URL drifted"
require_text "$vm_script" \
  "image_sha512='67dcf10dc67b807596c21b36fcd0a752838c124420774737d4badc46cb115b88cc879fac91a22d149d74b2ecd9600a7b4761690900348726e718f501a8564131'" \
  "Debian cloud image checksum drifted"
require_text "$vm_script" 'sha512sum --check --status' \
  "Debian cloud image checksum is not enforced"
require_text "$vm_script" 'info.get("backing-filename") is not None' \
  "base image backing-file rejection is missing"
require_text "$vm_script" '-accel tcg,thread=multi' \
  "QEMU is not forced to use software TCG"
require_text "$vm_script" \
  '-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22"' \
  "guest SSH is not loopback-forwarded"
require_text "$vm_script" \
  'RECASAOS_SYSTEMD_TEST_TARGET=debian-11-systemd-247-qemu' \
  "guest is not bound to the Debian 11 qualification target"
require_text "$vm_script" \
  'RECASAOS_HOSTILE_STORAGE_VM_CI=1' \
  "guest hostile-storage opt-in is missing"
for guest_package in dmsetup e2fsprogs kmod udev; do
  require_exact_line "$vm_script" "  - $guest_package" \
    "guest hostile-storage package is missing: $guest_package"
done
for identity_proof in \
  '[[ "$guest_release" == debian:11 ]]' \
  '[[ "$guest_pid1" == systemd ]]' \
  '[[ "$guest_systemd" == systemd\ 247* ]]' \
  '[[ "$guest_manager" == 247* ]]' \
  '[[ "$guest_virt" == qemu ]]' \
  '[[ "$guest_cgroup" == cgroup2fs ]]' \
  '"$guest_root_bytes" -ge 6442450944'
do
  require_text "$vm_script" "$identity_proof" \
    "guest identity proof is missing: $identity_proof"
done
for forbidden in \
  /dev/kvm \
  -enable-kvm \
  '-accel kvm' \
  -virtfs \
  -fsdev \
  --privileged \
  'docker run' \
  'podman run' \
  'eval '
do
  forbid_text "$vm_script" "$forbidden" \
    "VM script contains forbidden host escape or indirection: $forbidden"
done

require_text "$systemd_script" \
  'debian-11-systemd-247-qemu)' \
  "systemd integration does not recognize the exact Debian VM target"
require_text "$systemd_script" \
  'workspace_parent=/var/lib' \
  "Debian test workspace is not on the reviewed executable filesystem"
require_text "$systemd_script" \
  '    worker_capacity_window_seconds=15' \
  "native hosted capacity window drifted"
require_text "$systemd_script" \
  '    worker_capacity_window_seconds=30' \
  "Debian TCG capacity window drifted"
require_text "$systemd_script" \
  'worker_capacity_deadline=$((SECONDS + worker_capacity_window_seconds))' \
  "capacity phase does not use the reviewed target-specific window"
require_text "$systemd_script" \
  'worker_capacity_evidence_window_seconds=10' \
  "capacity evidence window drifted"
require_text "$systemd_script" \
  '  SECONDS + worker_capacity_evidence_window_seconds' \
  "capacity evidence does not use its reviewed bounded window"
require_text "$systemd_script" \
  'for _ in {1..8}; do' \
  "capacity holders are not launched without per-worker serialization"
require_text "$systemd_script" \
  '  slow_downloads_are_healthy' \
  "capacity phase does not require all eight clients to become ready"
require_exact_line "$systemd_script" \
  'assert_bounded_storage_worker_runtime_boundaries' \
  "bounded workers do not receive one fail-closed runtime inspection"
require_text "$systemd_script" \
  'bounded worker evidence sentinels are not unique' \
  "bounded worker Python source is not self-validated"
require_text "$systemd_script" \
  '    or len(worker_pairs) != 8' \
  "bounded runtime inspection does not require eight worker identities"
require_text "$systemd_script" \
  '    if contains_secret(command_before) or contains_secret(environment):' \
  "bounded runtime inspection does not scan command and environment bytes"
require_text "$systemd_script" \
  '        if os.readlink(descriptor_path) == listener_target:' \
  "bounded runtime inspection does not reject the AF_INET listener"
require_text "$systemd_script" \
  '        if len(flags) != 1 or (int(flags[0], 8) & os.O_CLOEXEC) == 0:' \
  "bounded runtime inspection does not enforce close-on-exec"
require_text "$systemd_script" \
  '[[ "$manager_version" == "$systemd_version" ]]' \
  "systemd integration does not compare binary and manager versions"
require_text "$systemd_script" \
  'start_cgroup_memory_sampler' \
  "systemd integration does not start reviewed memory sampling"
require_text "$systemd_script" \
  'stop_cgroup_memory_sampler' \
  "systemd integration does not stop reviewed memory sampling"
require_text "$systemd_script" \
  'systemd MemoryPeak is unavailable on a target that requires it' \
  "MemoryPeak fallback does not fail closed on newer targets"
require_text "$systemd_script" \
  'elif [[ "${RECASAOS_SYSTEMD_TEST_TARGET:-}" != \' \
  "MemoryPeak fallback does not reject every other target"
require_text "$systemd_script" \
  '  debian-11-systemd-247-qemu ]]; then' \
  "MemoryPeak fallback does not name the exact legacy target"
require_text "$systemd_script" \
  'fail "hostile-storage testing is forbidden on the host runner"' \
  "host runner does not fail closed against hostile-storage testing"
require_exact_line "$systemd_script" \
  '    hostile_storage_test_enabled=0' \
  "host runner unexpectedly enables hostile-storage testing"
require_text "$systemd_script" \
  'fail "the Debian VM hostile-storage opt-in is missing"' \
  "Debian hostile-storage opt-in is not mandatory"
require_exact_line "$systemd_script" \
  '    hostile_storage_test_enabled=1' \
  "Debian VM does not enable hostile-storage testing"
require_text "$systemd_script" \
  'sudo dmsetup suspend --nolockfs --noflush "$hostile_storage_name"' \
  "hostile-storage suspension does not avoid filesystem sync and I/O flush"
require_text "$systemd_script" \
  'storage_workers_are_in_d_state 4' \
  "hostile-storage phase does not require four real D-state workers"
require_exact_count "$systemd_script" \
  '  hostile_blocked_deadline=$((SECONDS + 8))' \
  1 \
  "hostile-storage D-state formation deadline is not the reviewed 8 seconds"
require_exact_count "$systemd_script" \
  '    "$hostile_blocked_deadline" \' \
  3 \
  "hostile-storage formation waits do not share exactly one deadline"
command -v python3 >/dev/null 2>&1 ||
  fail "Python is unavailable for hostile-storage policy parsing"
if ! python3 - "$systemd_script" <<'PYTHON'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
python_start = "<<'HOSTILE_PYTHON'\nimport os"
python_end = "\nHOSTILE_PYTHON\n  then"
if source.count(python_start) != 1 or source.count(python_end) != 1:
    raise SystemExit("hostile-storage Python sentinels are not unique")
worker_python = "import os" + source.split(python_start, 1)[1].split(
    python_end, 1
)[0]
signal_policy = """    pending_values = []
    for name in (b"SigPnd", b"ShdPnd"):
        value = status.get(name, b"")
        try:
            pending_values.append(int(value, 16))
        except ValueError as error:
            raise RuntimeError("invalid pending-signal evidence") from error
    kill_is_pending = any(value & kill_bit for value in pending_values)
    if phase == "blocked" and kill_is_pending:
        raise RuntimeError(
            f"hostile-storage worker {pid} already has pending SIGKILL"
        )
    if phase == "kill-pending" and not kill_is_pending:
        raise RuntimeError(
            f"hostile-storage worker {pid} has no pending SIGKILL"
        )
"""
if worker_python.count(signal_policy) != 1:
    raise SystemExit("hostile-storage pending-signal policy changed")
for task_proof in (
    'task_root = Path("/proc") / str(pid) / "task"',
    'if task_state == b"D":',
    'f"hostile-storage worker {pid} has no D-state task"',
    "d_tid, d_start_before = find_d_state_task(pid)",
    'if d_state_after != b"D" or d_start_after != d_start_before:',
):
    if worker_python.count(task_proof) != 1:
        raise SystemExit("hostile-storage thread-level D-state proof changed")

poll_start = (
    "<<'D_STATE_PYTHON' \\\n"
    "    >/dev/null 2>&1\n"
    "from pathlib import Path"
)
poll_end = "\nD_STATE_PYTHON\n}"
if source.count(poll_start) != 1 or source.count(poll_end) != 1:
    raise SystemExit("D-state polling Python sentinels are not unique")
poll_python = "from pathlib import Path" + source.split(
    poll_start, 1
)[1].split(poll_end, 1)[0]
compile(poll_python, "storage_workers_are_in_d_state.py", "exec")
for poll_proof in (
    'task_root = Path("/proc") / pid_text / "task"',
    'if task_state(task / "stat") == b"D":',
    "if not has_d_state_task:",
):
    if poll_python.count(poll_proof) != 1:
        raise SystemExit("D-state polling no longer checks every worker task set")

phase_start = """if [[ "$hostile_storage_test_enabled" == 1 ]]; then
  wait_until "storage workers before hostile-storage test"""
phase_end = "  hostile_timeout_deadline=$((SECONDS + 18))"
launch_start = "  hostile_blocked_deadline=$((SECONDS + 8))"
if source.count(phase_start) != 1 or source.count(phase_end) != 1:
    raise SystemExit("hostile-storage live phase sentinels are not unique")
live_phase = source.split(phase_start, 1)[1].split(phase_end, 1)[0]
if live_phase.count(launch_start) != 1:
    raise SystemExit("hostile-storage client launch is not unique in live phase")
formation = live_phase[live_phase.index(launch_start) :]
expected = """  hostile_blocked_deadline=$((SECONDS + 8))
  for _ in {1..4}; do
    start_hostile_storage_client
  done
  wait_until_before "four live hostile-storage clients" \\
    "$hostile_blocked_deadline" \\
    hostile_storage_clients_are_live
  wait_until_before "four hostile-storage workers" \\
    "$hostile_blocked_deadline" \\
    storage_worker_count_is 4
  wait_until_before "four real D-state storage workers" \\
    "$hostile_blocked_deadline" \\
    storage_workers_are_in_d_state 4
  mapfile -t hostile_worker_pids < <(storage_worker_pids)
  [[ "${#hostile_worker_pids[@]}" == 4 ]] ||
    fail "hostile-storage load did not retain exactly four workers"
  for hostile_worker_pid in "${hostile_worker_pids[@]}"; do
    hostile_worker_start_time="$(
      process_start_time "$hostile_worker_pid"
    )" || fail "could not capture hostile-storage worker identity"
    hostile_worker_start_times+=("$hostile_worker_start_time")
  done
  assert_hostile_storage_worker_boundaries blocked "$portal_pid"
  hostile_storage_clients_are_live ||
    fail "hostile-storage clients exited during blocked worker inspection"

"""
if formation != expected:
    raise SystemExit("hostile-storage live formation sequence changed")
PYTHON
then
  fail "hostile-storage formation sequence changed"
fi
require_text "$systemd_script" \
  'or len(worker_pairs) != 4' \
  "hostile-storage runtime inspection does not require four workers"
require_text "$systemd_script" \
  'if task_state == b"D":' \
  "hostile-storage runtime inspection does not require a D-state task"
require_text "$systemd_script" \
  'if phase == "kill-pending" and not kill_is_pending:' \
  "hostile-storage runtime inspection does not require pending SIGKILL"
require_text "$systemd_script" \
  'if phase == "blocked" and kill_is_pending:' \
  "hostile-storage blocked phase permits pending SIGKILL"
require_text "$systemd_script" \
  'fail "hostile-storage clients exited during blocked worker inspection"' \
  "hostile-storage blocked inspection does not recheck client liveness"
require_text "$systemd_script" \
  'assert_hostile_storage_worker_boundaries kill-pending 1' \
  "hostile-storage restart does not prove orphaned D-state worker identity"
require_text "$systemd_script" \
  'if ! resume_hostile_storage_for_cleanup; then' \
  "hostile-storage cleanup does not resume I/O before stopping systemd"
require_text "$systemd_script" \
  'sudo dmsetup remove --retry "$hostile_storage_name"' \
  "hostile-storage cleanup does not remove the exact device mapping"
require_text "$systemd_script" \
  'sudo losetup --detach "$hostile_storage_loop"' \
  "hostile-storage cleanup does not detach the exact loop device"
require_text "$systemd_script" \
  'real device-mapper D-state recovery passed:' \
  "hostile-storage phase has no explicit success evidence"

for sampler_proof in \
  'MAX_RUNTIME_SECONDS = 30.0' \
  'SAMPLE_INTERVAL_SECONDS = 0.01' \
  'source_flags |= os.O_NOFOLLOW' \
  'stat.S_IMODE(metadata.st_mode) != 0o600' \
  'os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC'
do
  require_text "$sampler" "$sampler_proof" \
    "memory sampler proof is missing: $sampler_proof"
done

printf 'Debian 11 systemd VM policy check passed\n'
