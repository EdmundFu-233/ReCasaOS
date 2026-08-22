#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files systemd test failed: %s\n' "$*" >&2
  exit 1
}

[[ "${RECASAOS_TRUSTED_SYSTEMD_CI:-0}" == 1 ]] ||
  fail "explicit trusted-CI opt-in is missing"
[[ "${GITHUB_ACTIONS:-}" == true ]] ||
  fail "this destructive integration test is restricted to GitHub Actions"
[[ "${GITHUB_REPOSITORY:-}" == "EdmundFu-233/ReCasaOS" ]] ||
  fail "the repository identity is not the trusted ReCasaOS repository"
[[ "${RUNNER_OS:-}" == Linux ]] ||
  fail "the runner is not Linux"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ID is missing or unsafe"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ATTEMPT is missing or unsafe"
[[ "$(cat /proc/1/comm)" == systemd ]] ||
  fail "PID 1 is not systemd"
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] ||
  fail "the runner is not using cgroup v2"
systemd_version_output="$(systemd --version)" ||
  fail "could not inspect the systemd manager version"
systemd_version_line="${systemd_version_output%%$'\n'*}"
IFS=' ' read -r systemd_command systemd_version _ <<<"$systemd_version_line"
[[ "$systemd_command" == systemd && "$systemd_version" =~ ^[0-9]+$ ]] ||
  fail "systemd reported an invalid version: $systemd_version_line"
manager_version_output="$(
  systemctl show --property=Version --value
)" || fail "could not inspect the running systemd manager version"
[[ "$manager_version_output" =~ ^([0-9]+) ]] ||
  fail "systemd manager reported an invalid version: $manager_version_output"
manager_version="${BASH_REMATCH[1]}"
[[ "$manager_version" == "$systemd_version" ]] ||
  fail "systemd binary version $systemd_version differs from manager $manager_version"
printf 'verified systemd manager version: %s\n' "$manager_version_output"

case "${RECASAOS_SYSTEMD_TEST_TARGET:-}" in
  github-hosted-ubuntu)
    [[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted ]] ||
      fail "GitHub did not identify this as a hosted runner"
    [[ -d /opt/hostedtoolcache ]] ||
      fail "the GitHub-hosted runner marker is missing"
    workspace_parent=/run
    worker_capacity_window_seconds=15
    hostile_storage_test_enabled=0
    [[ "${RECASAOS_HOSTILE_STORAGE_VM_CI:-0}" == 0 ]] ||
      fail "hostile-storage testing is forbidden on the host runner"
    ;;
  debian-11-systemd-247-qemu)
    [[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted-vm ]] ||
      fail "the Debian qualification target is not the expected hosted VM"
    [[ "$systemd_version" == 247 ]] ||
      fail "the Debian qualification VM is not running systemd 247"
    guest_release="$(
      . /etc/os-release
      printf '%s:%s\n' "${ID:-}" "${VERSION_ID:-}"
    )" || fail "could not inspect the Debian qualification release"
    [[ "$guest_release" == debian:11 ]] ||
      fail "the qualification VM release is $guest_release, want debian:11"
    if systemd-detect-virt --container >/dev/null 2>&1; then
      fail "the Debian qualification target is a container"
    fi
    [[ "$(systemd-detect-virt --vm)" == qemu ]] ||
      fail "the Debian qualification target is not an isolated QEMU VM"
    # Debian mounts /run with noexec. Keep the disposable RootDirectory and
    # both reviewed binaries below a root-owned executable filesystem instead.
    workspace_parent=/var/lib
    # QEMU TCG serializes enough CPU work that eight individually bounded
    # worker admissions do not reliably fit the native runner's aggregate
    # 15-second orchestration window. This changes only the test harness's
    # aggregate deadline; application IPC and service timeouts remain fixed.
    worker_capacity_window_seconds=30
    [[ "${RECASAOS_HOSTILE_STORAGE_VM_CI:-0}" == 1 ]] ||
      fail "the Debian VM hostile-storage opt-in is missing"
    hostile_storage_test_enabled=1
    ;;
  *)
    fail "the exact systemd integration target is not authorized"
    ;;
esac
# Journal visibility is evidence collection after admission, not additional
# worker-start budget. Keep it separately and identically bounded on both
# targets so a slow journal cannot silently widen the capacity requirement.
worker_capacity_evidence_window_seconds=10

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd -- "$repo_root"
run_key="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
workspace="${workspace_parent}/recasaos-public-files-ci-${run_key}"
service_unit="recasaos-public-files.service"
socket_unit="recasaos-public-files.socket"
sentinel_unit="recasaos-ci-management-${run_key}.service"
service_path="/run/systemd/system/${service_unit}"
socket_path="/run/systemd/system/${socket_unit}"
override_dir="/run/systemd/system/${service_unit}.d"
override_path="${override_dir}/ci.conf"
socket_override_dir="/run/systemd/system/${socket_unit}.d"
socket_override_path="${socket_override_dir}/ci.conf"
rootfs="${workspace}/rootfs"
share="${workspace}/share"
verifier="${workspace}/public-file.verifier"
good_verifier="${workspace}/public-file.verifier.good"
production_binary="${workspace}/recasaos-public-files-production"
systemd_test_binary="${workspace}/recasaos-public-files-systemd-test"
management_dir="${workspace}/management"
response_file="${workspace}/response"
ninth_response_headers="${workspace}/ninth-response.headers"
capacity_events="${workspace}/capacity-events"
memory_sampler_output="${workspace}/memory-current-sampled-peak"
memory_sampler_ready="${workspace}/memory-current-sampler-ready"
memory_sampler_stop="${workspace}/memory-current-sampler-stop"
memory_sampler_failure="${workspace}/memory-current-sampler-failure"
nested_backing="${workspace}/nested-backing"
nested_mount="${share}/covered"
hostile_storage_fuse_source="${workspace}/hostile-storage-fuse-source"
hostile_storage_fuse_mount="${workspace}/hostile-storage-fuse-mount"
hostile_storage_fuse_log="${workspace}/hostile-storage-fuse.log"
# bindfs sets fsname, which suppresses libfuse 2's automatic subtype. Keep an
# explicit subtype so mountinfo can prove fuse.bindfs instead of plain fuse.
hostile_storage_fuse_options='nodev,nosuid,noexec,subtype=bindfs,attr_timeout=0,entry_timeout=0,negative_timeout=0'
hostile_storage_backing_source="${hostile_storage_fuse_source}/hostile-storage.img"
hostile_storage_backing="${hostile_storage_fuse_mount}/hostile-storage.img"
hostile_storage_name="recasaos-dstate-${run_key}"
hostile_storage_mapper="/dev/mapper/${hostile_storage_name}"
hostile_storage_nbd_device=/dev/nbd0
hostile_storage_nbd_export="recasaos-hostile-${run_key}"
hostile_storage_nbd_log="${workspace}/hostile-storage-nbd.log"
hostile_storage_nbd_pid_file="${workspace}/hostile-storage-nbd.pid"
hostile_storage_nbd_port=10925
host_shm_sentinel_prefix="/dev/shm/recasaos-public-files-ci-${run_key}."
host_shm_sentinel=
test_bearer='rc1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
# The fixture is sparse. The dedicated CI-tagged worker returns its first real
# chunk, then stops itself only for this exact file so the HTTP client can
# validate committed response headers before worker-capacity checks begin.
worker_load_bytes=67108864
storage_worker_address_space_ceiling=2147483648
storage_worker_address_space_minimum_reserve=134217728

[[ "$workspace" =~ ^/(run|var/lib)/recasaos-public-files-ci-[0-9]+-[0-9]+$ &&
  "$workspace" == "$workspace_parent/recasaos-public-files-ci-$run_key" ]] ||
  fail "refusing unsafe workspace path: $workspace"
[[ "$host_shm_sentinel_prefix" =~ ^/dev/shm/recasaos-public-files-ci-[0-9]+-[0-9]+\.$ ]] ||
  fail "refusing unsafe shared-memory sentinel prefix: $host_shm_sentinel_prefix"
[[ "$hostile_storage_name" =~ ^recasaos-dstate-[0-9]+-[0-9]+$ &&
  "$hostile_storage_mapper" == "/dev/mapper/$hostile_storage_name" ]] ||
  fail "refusing unsafe hostile-storage device name: $hostile_storage_name"
[[ "$hostile_storage_fuse_source" == "$workspace/hostile-storage-fuse-source" &&
  "$hostile_storage_fuse_mount" == "$workspace/hostile-storage-fuse-mount" &&
  "$hostile_storage_fuse_log" == "$workspace/hostile-storage-fuse.log" &&
  "$hostile_storage_fuse_options" == 'nodev,nosuid,noexec,subtype=bindfs,attr_timeout=0,entry_timeout=0,negative_timeout=0' &&
  "$hostile_storage_backing_source" == "$hostile_storage_fuse_source/hostile-storage.img" &&
  "$hostile_storage_backing" == "$hostile_storage_fuse_mount/hostile-storage.img" ]] ||
  fail "refusing unsafe hostile-storage FUSE identity"
[[ "$hostile_storage_nbd_device" == /dev/nbd0 &&
  "$hostile_storage_nbd_export" =~ ^recasaos-hostile-[0-9]+-[0-9]+$ &&
  "$hostile_storage_nbd_log" == "$workspace/hostile-storage-nbd.log" &&
  "$hostile_storage_nbd_pid_file" == \
    "$workspace/hostile-storage-nbd.pid" &&
  "$hostile_storage_nbd_port" == 10925 ]] ||
  fail "refusing unsafe hostile-storage NBD identity"

[[ ! -e "$workspace" ]] || fail "test workspace already exists"
[[ ! -e "$service_path" && ! -e "$socket_path" &&
  ! -e "$override_dir" && ! -e "$socket_override_dir" ]] ||
  fail "test unit paths already exist"
if systemctl cat "$service_unit" >/dev/null 2>&1 ||
  systemctl cat "$socket_unit" >/dev/null 2>&1; then
  fail "a public-files unit is already installed on the runner"
fi
if getent passwd recasaos-public >/dev/null ||
  getent group recasaos-public >/dev/null; then
  fail "the recasaos-public account unexpectedly already exists"
fi
for required_tool in \
  cmp find findmnt getfacl go mktemp mount pgrep ps readlink sort ss systemctl \
  truncate umount wc
do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "required mount test tool is unavailable: $required_tool"
done
if [[ "$hostile_storage_test_enabled" == 1 ]]; then
  for required_tool in \
    bindfs blockdev dmsetup fusermount lsblk mkfs.ext4 modprobe \
    nbd-client qemu-nbd sync udevadm
  do
    command -v "$required_tool" >/dev/null 2>&1 ||
      fail "required hostile-storage VM tool is unavailable: $required_tool"
  done
fi
go_version="$(go version)" || fail "could not inspect the Go toolchain"
[[ "$go_version" == "go version go1.26.6 linux/amd64" ]] ||
  fail "unexpected Go toolchain: $go_version"
[[ -x /usr/bin/python3 ]] ||
  fail "required Python interpreter is unavailable: /usr/bin/python3"
/usr/bin/python3 - \
  "$repo_root/.github/scripts/test-public-files-systemd.sh" <<'PYTHON'
from pathlib import Path
import sys

script = Path(sys.argv[1]).read_text(encoding="utf-8")
start = "    /usr/bin/python3 -c '\n"
end = "\n' \"$ready_file\" \"$worker_load_bytes\" 2>\"$failure_file\" &"
if script.count(start) != 1 or script.count(end) != 1:
    raise SystemExit("slow download holder sentinels are not unique")
source = script.split(start, 1)[1].split(end, 1)[0]
if "'" in source:
    raise SystemExit(
        "slow download holder contains a shell-breaking single quote"
    )
compile(source, "start_slow_download.py", "exec")

limit_start = (
    "    \"$storage_worker_address_space_minimum_reserve\" <<'PYTHON'\n"
)
limit_end = (
    "\nPYTHON\n}\n\n"
    "assert_bounded_storage_worker_runtime_boundaries()"
)
if script.count(limit_start) != 1 or script.count(limit_end) != 1:
    raise SystemExit("address-space evidence sentinels are not unique")
limit_source = script.split(limit_start, 1)[1].split(limit_end, 1)[0]
compile(
    limit_source,
    "assert_storage_worker_address_space_limit.py",
    "exec",
)

bounded_start = (
    '    "${worker_identity_arguments[@]}" '
    "<<'BOUNDED_PYTHON'\n"
)
bounded_end = (
    "\nBOUNDED_PYTHON\n"
    "  then\n"
    '    fail "bounded storage worker runtime evidence failed"\n'
    "  fi\n"
    "}\n\n"
    "print_capacity_journal_diagnostics()"
)
if script.count(bounded_start) != 1 or script.count(bounded_end) != 1:
    raise SystemExit("bounded worker evidence sentinels are not unique")
bounded_source = script.split(bounded_start, 1)[1].split(bounded_end, 1)[0]
compile(
    bounded_source,
    "assert_bounded_storage_worker_runtime_boundaries.py",
    "exec",
)

hostile_start = (
    '    "${hostile_worker_identity_arguments[@]}" '
    "<<'HOSTILE_PYTHON'\n"
)
hostile_end = (
    "\nHOSTILE_PYTHON\n"
    "  then\n"
    '    fail "hostile-storage worker evidence failed"\n'
    "  fi\n"
    "}\n\n"
    "hostile_storage_clients_are_live()"
)
if script.count(hostile_start) != 1 or script.count(hostile_end) != 1:
    raise SystemExit("hostile-storage worker evidence sentinels are not unique")
hostile_source = script.split(hostile_start, 1)[1].split(hostile_end, 1)[0]
compile(
    hostile_source,
    "assert_hostile_storage_worker_boundaries.py",
    "exec",
)
d_state_start = (
    "<<'D_STATE_PYTHON' \\\n"
    "    >/dev/null 2>&1\n"
)
d_state_end = "\nD_STATE_PYTHON\n}"
if script.count(d_state_start) != 1 or script.count(d_state_end) != 1:
    raise SystemExit("D-state polling Python sentinels are not unique")
d_state_source = script.split(d_state_start, 1)[1].split(d_state_end, 1)[0]
compile(
    d_state_source,
    "storage_workers_are_in_d_state.py",
    "exec",
)
PYTHON
/usr/bin/python3 -c '
import os
import signal

if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(1)
' || fail "Python pidfd signaling support is unavailable"
systemctl_help="$(LC_ALL=C systemctl --help)" ||
  fail "could not inspect systemctl kill option compatibility"
systemctl_kill_selector=
# systemd 247 documents --kill-who; newer releases document --kill-whom.
# Select only an option that this exact runner advertises.
if grep -Fq -- '--kill-whom=WHOM' <<<"$systemctl_help"; then
  systemctl_kill_selector='--kill-whom=main'
fi
if grep -Fq -- '--kill-who=WHO' <<<"$systemctl_help"; then
  [[ -z "$systemctl_kill_selector" ]] ||
    fail "systemctl exposes ambiguous kill selector options"
  systemctl_kill_selector='--kill-who=main'
fi
[[ -n "$systemctl_kill_selector" ]] ||
  fail "systemctl exposes no supported exact kill selector option"
account_cleanup_authorized=1
nested_mount_cleanup_required=0
host_shm_sentinel_created=0
hostile_storage_dm_created=0
hostile_storage_share_mounted=0
hostile_storage_major=
hostile_storage_minor=
hostile_storage_suspended_path=
hostile_storage_nbd_connected=0
hostile_storage_nbd_server_executable=
hostile_storage_nbd_server_pid=
hostile_storage_nbd_server_start_time=
hostile_storage_nbd_server_started=0
hostile_storage_nbd_server_stopped=0
hostile_storage_fuse_connection=
hostile_storage_fuse_control_mounted=0
hostile_storage_fuse_daemon_executable=
hostile_storage_fusermount_executable=
hostile_storage_fuse_daemon_pid=
hostile_storage_fuse_daemon_start_time=
hostile_storage_fuse_daemon_started=0
hostile_storage_fuse_daemon_stopped=0
hostile_storage_fuse_mounted=0
hostile_storage_clients=()
hostile_storage_client_start_times=()
hostile_storage_client_prefixes=()
hostile_storage_client_sequence=0
hostile_worker_pids=()
hostile_worker_start_times=()
slow_download_pids=()
slow_download_ready_files=()
slow_download_failure_files=()
slow_download_start_times=()
slow_download_sequence=0
bounded_worker_pids=()
bounded_worker_start_times=()
latest_slow_download_pid=
latest_slow_download_ready_file=
latest_slow_download_failure_file=
latest_slow_download_start_time=
last_storage_worker_count=0
max_storage_worker_count=0
portal_invocation=
capacity_journal_cursor=
memory_sampler_pid=
memory_sampler_start_time=
sampled_memory_peak=

cleanup_problem() {
  printf 'public-files systemd test cleanup: %s\n' "$*" >&2
  cleanup_failed=1
}

cleanup_stop_unit() {
  local unit=$1
  local load_state
  local active_state
  local command_status
  local stop_status

  load_state="$(
    sudo systemctl show --property=LoadState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not query $unit before stopping it (status $command_status)"
    return 1
  fi
  if [[ -z "$load_state" ]]; then
    cleanup_problem "systemd returned an empty LoadState for $unit"
    return 1
  fi

  active_state="$(
    sudo systemctl show --property=ActiveState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not query $unit state before stopping it (status $command_status)"
    return 1
  fi
  if [[ -z "$active_state" ]]; then
    cleanup_problem "systemd returned an empty ActiveState for $unit"
    return 1
  fi
  if [[ "$load_state" == not-found && "$active_state" == inactive ]]; then
    return 0
  fi
  if [[ "$active_state" == inactive ]]; then
    return 0
  fi

  sudo systemctl stop "$unit" >/dev/null
  stop_status=$?
  if [[ "$stop_status" != 0 ]]; then
    cleanup_problem "could not stop $unit (status $stop_status)"
  fi

  active_state="$(
    sudo systemctl show --property=ActiveState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not verify $unit after stopping it (status $command_status)"
    return 1
  fi
  if [[ "$active_state" != inactive && "$active_state" != failed ]]; then
    cleanup_problem \
      "$unit remains in ActiveState=${active_state:-unknown} after stop"
    return 1
  fi
  [[ "$stop_status" == 0 ]] || return 1
  return 0
}

cleanup_unit_cgroup_is_empty() {
  local unit=$1
  local recorded_control_group=${2-}
  local control_group
  local command_status
  local cgroup_path
  local populated
  local remaining_pids

  if [[ "$#" == 2 ]]; then
    control_group=$recorded_control_group
  else
    control_group="$(
      sudo systemctl show --property=ControlGroup --value "$unit"
    )"
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not query $unit cgroup before cleanup (status $command_status)"
      return 1
    fi
  fi
  if [[ -z "$control_group" ]]; then
    return 0
  fi
  case "$control_group" in
    /*)
      if [[ "$control_group" == *"/../"* ||
        "$control_group" == */.. ||
        "$control_group" == *$'\n'* ]]; then
        cleanup_problem "refusing unsafe $unit cgroup path: $control_group"
        return 1
      fi
      ;;
    *)
      cleanup_problem "refusing non-absolute $unit cgroup path: $control_group"
      return 1
      ;;
  esac
  cgroup_path="/sys/fs/cgroup${control_group}"
  if [[ ! -e "$cgroup_path" ]]; then
    return 0
  fi
  if [[ ! -f "$cgroup_path/cgroup.events" ||
    ! -f "$cgroup_path/cgroup.procs" ]]; then
    cleanup_problem "$unit cgroup has no inspectable v2 process state"
    return 1
  fi
  populated="$(
    sudo awk '$1 == "populated" { count++; value = $2 }
      END {
        if (count != 1 || (value != 0 && value != 1))
          exit 1
        print value
      }' "$cgroup_path/cgroup.events"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem "could not validate $unit cgroup populated state"
    return 1
  fi
  remaining_pids="$(
    sudo awk 'NF {
      if (seen)
        printf ","
      printf "%s", $1
      seen = 1
    }' "$cgroup_path/cgroup.procs"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem "could not inspect $unit cgroup processes"
    return 1
  fi
  if [[ "$populated" != 0 || -n "$remaining_pids" ]]; then
    cleanup_problem \
      "$unit cgroup remains populated after stop (pids: ${remaining_pids:-descendant-subgroup})"
    return 1
  fi
  return 0
}

cleanup_reset_failed_unit() {
  local unit=$1
  local load_state
  local active_state
  local command_status

  load_state="$(
    sudo systemctl show --property=LoadState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not query $unit before resetting it (status $command_status)"
    return
  fi
  if [[ -z "$load_state" ]]; then
    cleanup_problem "systemd returned an empty LoadState for $unit"
    return
  fi

  active_state="$(
    sudo systemctl show --property=ActiveState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not query $unit failed state (status $command_status)"
    return
  fi
  if [[ -z "$active_state" ]]; then
    cleanup_problem "systemd returned an empty ActiveState for $unit"
    return
  fi
  if [[ "$load_state" == not-found && "$active_state" == inactive ]]; then
    return
  fi
  if [[ "$active_state" == failed ]]; then
    sudo systemctl reset-failed "$unit" >/dev/null
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not reset the failed state for $unit (status $command_status)"
    fi
  fi
}

cleanup_verify_unit_inactive() {
  local unit=$1
  local load_state
  local active_state
  local command_status

  load_state="$(
    sudo systemctl show --property=LoadState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not query $unit after cleanup (status $command_status)"
    return
  fi
  if [[ -z "$load_state" ]]; then
    cleanup_problem "systemd returned an empty LoadState for $unit"
    return
  fi

  active_state="$(
    sudo systemctl show --property=ActiveState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not verify $unit final state (status $command_status)"
    return
  fi
  if [[ -z "$active_state" ]]; then
    cleanup_problem "systemd returned an empty ActiveState for $unit"
    return
  fi
  if [[ "$load_state" == not-found && "$active_state" == inactive ]]; then
    return
  fi
  if [[ "$active_state" != inactive ]]; then
    cleanup_problem \
      "$unit remains in ActiveState=${active_state:-unknown} after cleanup"
  fi
}

cleanup_account_entry() {
  local database=$1
  local delete_command=$2
  local description=$3
  local lookup_status
  local delete_status

  getent "$database" recasaos-public >/dev/null
  lookup_status=$?
  case "$lookup_status" in
    0)
      sudo "$delete_command" recasaos-public >/dev/null
      delete_status=$?
      if [[ "$delete_status" != 0 ]]; then
        cleanup_problem \
          "could not remove test $description (status $delete_status)"
      fi
      ;;
    2)
      return
      ;;
    *)
      cleanup_problem \
        "could not query test $description (status $lookup_status)"
      return
      ;;
  esac

  getent "$database" recasaos-public >/dev/null
  lookup_status=$?
  case "$lookup_status" in
    0)
      cleanup_problem "test $description remains after cleanup"
      ;;
    2)
      ;;
    *)
      cleanup_problem \
        "could not verify test $description removal (status $lookup_status)"
      ;;
  esac
}

process_start_time() {
  local pid=$1
  local stat_line
  local -a stat_fields=()

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
  [[ -r "/proc/$pid/stat" ]] || return 1
  stat_line="$(<"/proc/$pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 19 &&
    "${stat_fields[19]}" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "${stat_fields[19]}"
}

signal_exact_background_process() {
  local pid=$1
  local start_time=$2
  local signal_number=$3

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 &&
    "$start_time" =~ ^[0-9]+$ &&
    ( "$signal_number" == 9 || "$signal_number" == 15 ||
      "$signal_number" == 18 || "$signal_number" == 19 ) ]] || return 1
  /usr/bin/python3 -c '
import os
import signal
import sys

pid = int(sys.argv[1])
expected_start = sys.argv[2].encode("ascii")
signal_number = int(sys.argv[3])
try:
    pidfd = os.pidfd_open(pid, 0)
except ProcessLookupError:
    raise SystemExit(0)
try:
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat_file:
            stat_data = stat_file.read()
    except FileNotFoundError:
        raise SystemExit(0)
    marker = stat_data.rfind(b") ")
    fields = stat_data[marker + 2:].split() if marker >= 0 else []
    if len(fields) <= 19 or not fields[19].isdigit():
        raise RuntimeError("could not parse exact process start time")
    if fields[19] != expected_start:
        raise SystemExit(0)
    try:
        signal.pidfd_send_signal(pidfd, signal_number, None, 0)
    except ProcessLookupError:
        pass
finally:
    os.close(pidfd)
' "$pid" "$start_time" "$signal_number"
}

terminate_exact_background_process() {
  signal_exact_background_process "$1" "$2" 15
}

kill_exact_background_process() {
  signal_exact_background_process "$1" "$2" 9
}

hostile_storage_fuse_daemon_is_exact() {
  local argument
  local capability_value
  local current_executable
  local current_start_time
  local uid_value
  local -a current_arguments=()

  [[ "$hostile_storage_fuse_daemon_started" == 1 &&
    "$hostile_storage_fuse_daemon_pid" =~ ^[0-9]+$ &&
    "$hostile_storage_fuse_daemon_pid" -gt 1 &&
    "$hostile_storage_fuse_daemon_start_time" =~ ^[0-9]+$ &&
    "$hostile_storage_fuse_daemon_executable" == /usr/bin/bindfs &&
    "$runner_uid" =~ ^[0-9]+$ && "$runner_uid" -gt 0 ]] || return 1
  current_start_time="$(
    process_start_time "$hostile_storage_fuse_daemon_pid" 2>/dev/null
  )" || return 1
  [[ "$current_start_time" == "$hostile_storage_fuse_daemon_start_time" ]] ||
    return 1
  current_executable="$(
    readlink -f "/proc/$hostile_storage_fuse_daemon_pid/exe" 2>/dev/null
  )" || return 1
  [[ "$current_executable" == "$hostile_storage_fuse_daemon_executable" ]] ||
    return 1
  while IFS= read -r -d '' argument; do
    current_arguments+=("$argument")
  done <"/proc/$hostile_storage_fuse_daemon_pid/cmdline"
  [[ "${#current_arguments[@]}" == 7 &&
    "${current_arguments[0]}" == /usr/bin/bindfs &&
    "${current_arguments[1]}" == -f &&
    "${current_arguments[2]}" == --no-allow-other &&
    "${current_arguments[3]}" == -o &&
    "${current_arguments[4]}" == "$hostile_storage_fuse_options" &&
    "${current_arguments[5]}" == "$hostile_storage_fuse_source" &&
    "${current_arguments[6]}" == "$hostile_storage_fuse_mount" ]] || return 1
  uid_value="$(
    awk '$1 == "Uid:" { print $2 ":" $3 ":" $4 ":" $5 }' \
      "/proc/$hostile_storage_fuse_daemon_pid/status"
  )" || return 1
  capability_value="$(
    awk '$1 == "CapEff:" { print $2 }' \
      "/proc/$hostile_storage_fuse_daemon_pid/status"
  )" || return 1
  [[ "$uid_value" == "$runner_uid:$runner_uid:$runner_uid:$runner_uid" &&
    "$capability_value" == 0000000000000000 ]]
}

hostile_storage_fuse_daemon_state_is() {
  local expected_state=$1
  local stat_line
  local -a stat_fields=()

  [[ "$expected_state" == T ]] || return 1
  hostile_storage_fuse_daemon_is_exact || return 1
  stat_line="$(<"/proc/$hostile_storage_fuse_daemon_pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 0 &&
    "${stat_fields[0]}" == "$expected_state" ]]
}

hostile_storage_fuse_daemon_is_resumed() {
  local stat_line
  local -a stat_fields=()

  hostile_storage_fuse_daemon_is_exact || return 1
  stat_line="$(<"/proc/$hostile_storage_fuse_daemon_pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 0 ]] || return 1
  case "${stat_fields[0]}" in
    T | t | X | x | Z) return 1 ;;
    R | S | D | I) return 0 ;;
    *) return 1 ;;
  esac
}

hostile_storage_fuse_daemon_process_is_gone() {
  local current_start_time
  local stat_line
  local -a stat_fields=()

  [[ "$hostile_storage_fuse_daemon_pid" =~ ^[0-9]+$ &&
    "$hostile_storage_fuse_daemon_pid" -gt 1 &&
    "$hostile_storage_fuse_daemon_start_time" =~ ^[0-9]+$ ]] || return 1
  current_start_time="$(
    process_start_time "$hostile_storage_fuse_daemon_pid" 2>/dev/null
  )" || return 0
  if [[ "$current_start_time" != "$hostile_storage_fuse_daemon_start_time" ]]; then
    return 0
  fi
  stat_line="$(<"/proc/$hostile_storage_fuse_daemon_pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 0 && "${stat_fields[0]}" == Z ]] || return 1
  wait "$hostile_storage_fuse_daemon_pid" 2>/dev/null || true
  current_start_time="$(
    process_start_time "$hostile_storage_fuse_daemon_pid" 2>/dev/null
  )" || return 0
  [[ "$current_start_time" != "$hostile_storage_fuse_daemon_start_time" ]]
}

signal_exact_hostile_storage_fuse_daemon() {
  local signal_number=$1

  [[ "$signal_number" == 18 || "$signal_number" == 19 ]] || return 1
  hostile_storage_fuse_daemon_is_exact || return 1
  signal_exact_background_process \
    "$hostile_storage_fuse_daemon_pid" \
    "$hostile_storage_fuse_daemon_start_time" \
    "$signal_number"
}

hostile_storage_fuse_waiting_value() {
  local waiting_path
  local waiting_value

  [[ "$hostile_storage_fuse_connection" =~ ^[0-9]+$ ]] || return 1
  waiting_path="/sys/fs/fuse/connections/$hostile_storage_fuse_connection/waiting"
  [[ "$waiting_path" =~ ^/sys/fs/fuse/connections/[0-9]+/waiting$ ]] ||
    return 1
  [[ -f "$waiting_path" && ! -L "$waiting_path" && -r "$waiting_path" ]] ||
    return 1
  waiting_value="$(<"$waiting_path")" || return 1
  [[ "$waiting_value" =~ ^[0-9]+$ ]] || return 1
  printf '%s\n' "$waiting_value"
}

hostile_storage_fuse_has_waiting_request() {
  local waiting_value

  hostile_storage_fuse_daemon_state_is T || return 1
  hostile_storage_nbd_server_is_resumed || return 1
  waiting_value="$(hostile_storage_fuse_waiting_value)" || return 1
  [[ "$waiting_value" -ge 1 ]]
}

hostile_storage_fuse_is_recovered() {
  local waiting_value

  hostile_storage_fuse_daemon_is_resumed || return 1
  hostile_storage_nbd_server_is_resumed || return 1
  waiting_value="$(hostile_storage_fuse_waiting_value)" || return 1
  [[ "$waiting_value" == 0 ]]
}

hostile_storage_nbd_server_is_exact() {
  local current_executable
  local current_start_time
  local current_uid

  [[ "$hostile_storage_nbd_server_started" == 1 &&
    "$hostile_storage_nbd_server_pid" =~ ^[0-9]+$ &&
    "$hostile_storage_nbd_server_pid" -gt 1 &&
    "$hostile_storage_nbd_server_start_time" =~ ^[0-9]+$ &&
    "$hostile_storage_nbd_server_executable" == /usr/bin/qemu-nbd ]] ||
    return 1
  current_start_time="$(
    process_start_time "$hostile_storage_nbd_server_pid" 2>/dev/null
  )" || return 1
  [[ "$current_start_time" == "$hostile_storage_nbd_server_start_time" ]] ||
    return 1
  current_executable="$(
    readlink -f "/proc/$hostile_storage_nbd_server_pid/exe" 2>/dev/null
  )" || return 1
  [[ "$current_executable" == "$hostile_storage_nbd_server_executable" ]] ||
    return 1
  current_uid="$(
    awk '$1 == "Uid:" { print $2; exit }' \
      "/proc/$hostile_storage_nbd_server_pid/status"
  )" || return 1
  [[ "$current_uid" == "$(id -u)" ]]
}

hostile_storage_nbd_server_state_is() {
  local expected_state=$1
  local stat_line
  local -a stat_fields=()

  [[ "$expected_state" == R || "$expected_state" == S ||
    "$expected_state" == T ]] || return 1
  hostile_storage_nbd_server_is_exact || return 1
  stat_line="$(<"/proc/$hostile_storage_nbd_server_pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 0 &&
    "${stat_fields[0]}" == "$expected_state" ]]
}

hostile_storage_nbd_server_is_resumed() {
  local stat_line
  local -a stat_fields=()

  hostile_storage_nbd_server_is_exact || return 1
  stat_line="$(<"/proc/$hostile_storage_nbd_server_pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 0 &&
    "${stat_fields[0]}" != T &&
    "${stat_fields[0]}" != t &&
    "${stat_fields[0]}" != X &&
    "${stat_fields[0]}" != x &&
    "${stat_fields[0]}" != Z ]]
}

hostile_storage_nbd_server_process_is_gone() {
  local stat_line
  local -a stat_fields=()

  [[ "$hostile_storage_nbd_server_pid" =~ ^[0-9]+$ &&
    "$hostile_storage_nbd_server_pid" -gt 1 &&
    "$hostile_storage_nbd_server_start_time" =~ ^[0-9]+$ ]] || return 1
  if process_identity_is_gone \
    "$hostile_storage_nbd_server_pid" \
    "$hostile_storage_nbd_server_start_time"; then
    return 0
  fi
  stat_line="$(<"/proc/$hostile_storage_nbd_server_pid/stat")" || return 1
  [[ "$stat_line" == *") "* ]] || return 1
  IFS=' ' read -r -a stat_fields <<<"${stat_line##*) }"
  [[ "${#stat_fields[@]}" -gt 0 && "${stat_fields[0]}" == Z ]] || return 1
  wait "$hostile_storage_nbd_server_pid" 2>/dev/null || true
  return 0
}

signal_exact_hostile_storage_nbd_server() {
  local signal_number=$1

  [[ "$signal_number" == 18 || "$signal_number" == 19 ]] || return 1
  hostile_storage_nbd_server_is_exact || return 1
  signal_exact_background_process \
    "$hostile_storage_nbd_server_pid" \
    "$hostile_storage_nbd_server_start_time" \
    "$signal_number"
}

hostile_storage_nbd_listener_is_exact() {
  hostile_storage_nbd_server_is_exact || return 1
  /usr/bin/python3 - \
    "$hostile_storage_nbd_server_pid" \
    "$hostile_storage_nbd_port" <<'NBD_LISTENER_PYTHON'
import os
from pathlib import Path
import sys

pid = int(sys.argv[1])
port = int(sys.argv[2])
socket_inodes = set()
for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
    try:
        target = os.readlink(descriptor)
    except FileNotFoundError:
        continue
    if target.startswith("socket:[") and target.endswith("]"):
        socket_inodes.add(target[8:-1])

wanted_address = f"0100007F:{port:04X}"
matches = []
with open("/proc/net/tcp", encoding="ascii") as tcp_table:
    next(tcp_table)
    for line in tcp_table:
        fields = line.split()
        if len(fields) >= 10 and fields[1] == wanted_address and fields[3] == "0A":
            matches.append(fields[9])
if len(matches) != 1 or matches[0] not in socket_inodes:
    raise SystemExit(1)
NBD_LISTENER_PYTHON
}

memory_sampler_process_is_live() {
  local current_start_time

  [[ "$memory_sampler_pid" =~ ^[0-9]+$ &&
    "$memory_sampler_pid" -gt 1 &&
    "$memory_sampler_start_time" =~ ^[0-9]+$ ]] || return 1
  current_start_time="$(
    process_start_time "$memory_sampler_pid" 2>/dev/null
  )" || return 1
  [[ "$current_start_time" == "$memory_sampler_start_time" ]]
}

memory_sampler_ready_is_valid() {
  local metadata
  local value

  [[ -f "$memory_sampler_ready" && ! -L "$memory_sampler_ready" ]] ||
    return 1
  metadata="$(stat -c '%u:%a:%h' "$memory_sampler_ready")" || return 1
  [[ "$metadata" == "$(id -u):600:1" ]] || return 1
  value="$(<"$memory_sampler_ready")" || return 1
  [[ "$value" =~ ^[0-9]+$ ]]
}

start_cgroup_memory_sampler() {
  local cgroup_memory_current
  local ready_deadline

  [[ -z "$memory_sampler_pid" && -z "$memory_sampler_start_time" ]] ||
    fail "cgroup memory sampler is already recorded"
  for control_path in \
    "$memory_sampler_output" \
    "$memory_sampler_ready" \
    "$memory_sampler_stop" \
    "$memory_sampler_failure"
  do
    [[ ! -e "$control_path" && ! -L "$control_path" ]] ||
      fail "cgroup memory sampler control path already exists: $control_path"
  done
  cgroup_memory_current="/sys/fs/cgroup/system.slice/${service_unit}/memory.current"
  [[ "$cgroup_memory_current" == \
    /sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.current ]] ||
    fail "refusing unexpected cgroup memory source: $cgroup_memory_current"
  [[ -f "$cgroup_memory_current" &&
    ! -L "$cgroup_memory_current" &&
    -r "$cgroup_memory_current" ]] ||
    fail "service cgroup memory.current is not a readable regular file"
  [[ -f "$repo_root/.github/scripts/sample-cgroup-memory.py" &&
    ! -L "$repo_root/.github/scripts/sample-cgroup-memory.py" ]] ||
    fail "reviewed cgroup memory sampler is unavailable"

  install -m 0600 /dev/null "$memory_sampler_failure"
  PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 \
    "$repo_root/.github/scripts/sample-cgroup-memory.py" \
    "$cgroup_memory_current" \
    "$memory_sampler_output" \
    "$memory_sampler_ready" \
    "$memory_sampler_stop" \
    2>"$memory_sampler_failure" &
  memory_sampler_pid=$!
  memory_sampler_start_time="$(
    process_start_time "$memory_sampler_pid"
  )" || fail "could not record the cgroup memory sampler identity"

  ready_deadline=$((SECONDS + 5))
  while ! memory_sampler_ready_is_valid; do
    ((SECONDS < ready_deadline)) || {
      sed -n '1,20p' "$memory_sampler_failure" >&2
      fail "cgroup memory sampler did not become ready"
    }
    memory_sampler_process_is_live || {
      sed -n '1,20p' "$memory_sampler_failure" >&2
      fail "cgroup memory sampler exited before becoming ready"
    }
    sleep 0.02
  done
}

stop_cgroup_memory_sampler() {
  local metadata
  local sampler_deadline

  memory_sampler_process_is_live ||
    fail "cgroup memory sampler identity disappeared before stop"
  [[ ! -e "$memory_sampler_stop" && ! -L "$memory_sampler_stop" ]] ||
    fail "cgroup memory sampler stop marker already exists"
  install -m 0600 /dev/null "$memory_sampler_stop"

  sampler_deadline=$((SECONDS + 5))
  while memory_sampler_process_is_live; do
    ((SECONDS < sampler_deadline)) || {
      terminate_exact_background_process \
        "$memory_sampler_pid" "$memory_sampler_start_time" || true
      fail "cgroup memory sampler did not stop within the deadline"
    }
    sleep 0.02
  done
  if ! wait "$memory_sampler_pid"; then
    sed -n '1,20p' "$memory_sampler_failure" >&2
    fail "cgroup memory sampler exited unsuccessfully"
  fi

  [[ -f "$memory_sampler_output" && ! -L "$memory_sampler_output" ]] ||
    fail "cgroup memory sampler output is unavailable"
  metadata="$(stat -c '%u:%a:%h' "$memory_sampler_output")" ||
    fail "could not inspect cgroup memory sampler output"
  [[ "$metadata" == "$(id -u):600:1" ]] ||
    fail "cgroup memory sampler output metadata is unsafe: $metadata"
  sampled_memory_peak="$(<"$memory_sampler_output")" ||
    fail "could not read cgroup memory sampler output"
  [[ "$sampled_memory_peak" =~ ^[0-9]+$ ]] ||
    fail "cgroup memory sampler output is invalid"

  memory_sampler_pid=
  memory_sampler_start_time=
}

cleanup_cgroup_memory_sampler() {
  local sampler_deadline

  if [[ ! "$memory_sampler_pid" =~ ^[0-9]+$ ||
    "$memory_sampler_pid" -le 1 ||
    ! "$memory_sampler_start_time" =~ ^[0-9]+$ ]]; then
    memory_sampler_pid=
    memory_sampler_start_time=
    return
  fi

  if [[ ! -e "$memory_sampler_stop" && ! -L "$memory_sampler_stop" ]]; then
    install -m 0600 /dev/null "$memory_sampler_stop" ||
      cleanup_problem "could not create cgroup memory sampler stop marker"
  fi
  if memory_sampler_process_is_live; then
    if ! terminate_exact_background_process \
      "$memory_sampler_pid" "$memory_sampler_start_time"; then
      cleanup_problem "could not terminate exact cgroup memory sampler identity"
    fi
  fi
  sampler_deadline=$((SECONDS + 3))
  while memory_sampler_process_is_live && ((SECONDS < sampler_deadline)); do
    sleep 0.02
  done
  if memory_sampler_process_is_live; then
    if ! kill_exact_background_process \
      "$memory_sampler_pid" "$memory_sampler_start_time"; then
      cleanup_problem "could not kill exact cgroup memory sampler identity"
    fi
    sampler_deadline=$((SECONDS + 2))
    while memory_sampler_process_is_live && ((SECONDS < sampler_deadline)); do
      sleep 0.02
    done
  fi
  if memory_sampler_process_is_live; then
    cleanup_problem "cgroup memory sampler remains live after exact SIGKILL"
  else
    wait "$memory_sampler_pid" 2>/dev/null || true
  fi
  memory_sampler_pid=
  memory_sampler_start_time=
}

cleanup_background_downloads() {
  local client_index
  local pid

  for client_index in "${!slow_download_pids[@]}"; do
    pid="${slow_download_pids[$client_index]}"
    if ! terminate_exact_background_process \
      "$pid" "${slow_download_start_times[$client_index]}"; then
      if [[ -n "${cleanup_failed+x}" ]]; then
        cleanup_problem \
          "could not terminate exact download client identity $pid"
      else
        fail "could not terminate exact download client identity $pid"
      fi
    fi
  done
  for pid in "${slow_download_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  slow_download_pids=()
  slow_download_ready_files=()
  slow_download_failure_files=()
  slow_download_start_times=()
  latest_slow_download_pid=
  latest_slow_download_ready_file=
  latest_slow_download_failure_file=
  latest_slow_download_start_time=
  last_storage_worker_count=0
  max_storage_worker_count=0
}

cleanup_hostile_storage_clients() {
  local client_index
  local pid

  for client_index in "${!hostile_storage_clients[@]}"; do
    pid="${hostile_storage_clients[$client_index]}"
    if ! terminate_exact_background_process \
      "$pid" "${hostile_storage_client_start_times[$client_index]}"; then
      cleanup_problem \
        "could not terminate exact hostile-storage client identity $pid"
    fi
  done
  for pid in "${hostile_storage_clients[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  hostile_storage_clients=()
  hostile_storage_client_start_times=()
  hostile_storage_client_prefixes=()
}

hostile_storage_suspended_value() {
  [[ "$hostile_storage_suspended_path" =~ \
    ^/sys/dev/block/[0-9]+:[0-9]+/dm/suspended$ ]] || return 1
  sudo test -f "$hostile_storage_suspended_path" || return 1
  sudo cat "$hostile_storage_suspended_path"
}

record_hostile_storage_device_identity() {
  local device_identity

  device_identity="$(
    sudo dmsetup info --columns --noheadings --separator : \
      -o major,minor "$hostile_storage_name" | tr -d '[:space:]'
  )" || return 1
  [[ "$device_identity" =~ ^([0-9]+):([0-9]+)$ ]] || return 1
  hostile_storage_major="${BASH_REMATCH[1]}"
  hostile_storage_minor="${BASH_REMATCH[2]}"
  hostile_storage_suspended_path="/sys/dev/block/${device_identity}/dm/suspended"
  [[ "$hostile_storage_suspended_path" =~ \
    ^/sys/dev/block/[0-9]+:[0-9]+/dm/suspended$ ]]
}

resume_hostile_storage_fuse_for_cleanup() {
  local resume_deadline

  [[ "$hostile_storage_test_enabled" == 1 ]] || return 0
  [[ "$hostile_storage_fuse_daemon_started" == 1 ]] || return 0
  if hostile_storage_fuse_daemon_process_is_gone; then
    hostile_storage_fuse_daemon_started=0
    hostile_storage_fuse_daemon_stopped=0
    return 0
  fi
  hostile_storage_fuse_daemon_is_exact || return 1
  if [[ "$hostile_storage_fuse_daemon_stopped" == 1 ]] ||
    hostile_storage_fuse_daemon_state_is T; then
    signal_exact_hostile_storage_fuse_daemon 18 || return 1
  fi
  resume_deadline=$((SECONDS + 5))
  while ! hostile_storage_fuse_daemon_is_resumed &&
    ((SECONDS < resume_deadline)); do
    sleep 0.02
  done
  hostile_storage_fuse_daemon_is_resumed || return 1
  hostile_storage_fuse_daemon_stopped=0
}

resume_hostile_storage_nbd_for_cleanup() {
  local resume_deadline

  [[ "$hostile_storage_test_enabled" == 1 ]] || return 0
  [[ "$hostile_storage_nbd_server_started" == 1 ]] || return 0
  if hostile_storage_nbd_server_process_is_gone; then
    hostile_storage_nbd_server_started=0
    hostile_storage_nbd_server_stopped=0
    return 0
  fi
  hostile_storage_nbd_server_is_exact || return 1
  if [[ "$hostile_storage_nbd_server_stopped" == 1 ]] ||
    hostile_storage_nbd_server_state_is T; then
    signal_exact_hostile_storage_nbd_server 18 || return 1
  fi
  resume_deadline=$((SECONDS + 5))
  while ! hostile_storage_nbd_server_is_resumed &&
    ((SECONDS < resume_deadline)); do
    sleep 0.02
  done
  hostile_storage_nbd_server_is_resumed || return 1
  hostile_storage_nbd_server_stopped=0
}

resume_hostile_storage_for_cleanup() {
  [[ "$hostile_storage_test_enabled" == 1 ]] || return 0
  resume_hostile_storage_fuse_for_cleanup || return 1
  resume_hostile_storage_nbd_for_cleanup
}

cleanup_hostile_storage_stack() {
  local command_status
  local connection_count
  local fuse_exit_deadline
  local fuse_mount_evidence
  local mount_count
  local server_exit_deadline

  [[ "$hostile_storage_test_enabled" == 1 ]] || return 0
  if [[ "$hostile_storage_share_mounted" == 1 ]]; then
    mount_count="$(
      awk -v target="$share" '$5 == target { count++ }
        END { print count + 0 }' /proc/self/mountinfo
    )"
    command_status=$?
    if [[ "$command_status" != 0 || "$mount_count" != 1 ]]; then
      cleanup_problem \
        "hostile-storage share has unsafe mount count: ${mount_count:-invalid}"
      workspace_removal_safe=0
      return 1
    fi
    sudo umount -- "$share"
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not unmount hostile-storage share (status $command_status)"
      workspace_removal_safe=0
      return 1
    fi
    hostile_storage_share_mounted=0
    if awk -v target="$share" '$5 == target { found = 1 }
      END { exit found ? 0 : 1 }' /proc/self/mountinfo; then
      cleanup_problem "hostile-storage share remains mounted"
      workspace_removal_safe=0
      return 1
    fi
  fi

  if [[ "$hostile_storage_dm_created" == 1 ]]; then
    sudo dmsetup remove --retry "$hostile_storage_name"
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not remove hostile-storage mapping (status $command_status)"
      workspace_removal_safe=0
      return 1
    fi
    hostile_storage_dm_created=0
    if sudo dmsetup info "$hostile_storage_name" >/dev/null 2>&1; then
      cleanup_problem "hostile-storage mapping remains after removal"
      workspace_removal_safe=0
      return 1
    fi
  fi

  if [[ "$hostile_storage_nbd_connected" == 1 ]]; then
    [[ "$hostile_storage_nbd_device" == /dev/nbd0 ]] || {
      cleanup_problem \
        "refusing unsafe hostile-storage NBD disconnect: $hostile_storage_nbd_device"
      workspace_removal_safe=0
      return 1
    }
    timeout --signal=TERM --kill-after=5s 10s \
      sudo nbd-client \
        --nonetlink \
        -d "$hostile_storage_nbd_device"
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not disconnect hostile-storage NBD device (status $command_status)"
      workspace_removal_safe=0
      return 1
    fi
    hostile_storage_nbd_connected=0
    sudo nbd-client -c "$hostile_storage_nbd_device" >/dev/null 2>&1
    command_status=$?
    if [[ "$command_status" == 0 ]]; then
      cleanup_problem "hostile-storage NBD device remains connected"
      workspace_removal_safe=0
      return 1
    fi
    if [[ "$command_status" != 1 ]]; then
      cleanup_problem \
        "could not verify hostile-storage NBD disconnect (status $command_status)"
      workspace_removal_safe=0
      return 1
    fi
  fi

  if [[ "$hostile_storage_nbd_server_started" == 1 ]]; then
    if ! hostile_storage_nbd_server_is_exact; then
      cleanup_problem \
        "hostile-storage NBD server identity changed before cleanup"
      workspace_removal_safe=0
      return 1
    fi
    if ! terminate_exact_background_process \
      "$hostile_storage_nbd_server_pid" \
      "$hostile_storage_nbd_server_start_time"; then
      cleanup_problem "could not terminate the exact hostile-storage NBD server"
      workspace_removal_safe=0
      return 1
    fi
    server_exit_deadline=$((SECONDS + 5))
    while ! hostile_storage_nbd_server_process_is_gone &&
      ((SECONDS < server_exit_deadline)); do
      sleep 0.02
    done
    if ! hostile_storage_nbd_server_process_is_gone; then
      if ! kill_exact_background_process \
        "$hostile_storage_nbd_server_pid" \
        "$hostile_storage_nbd_server_start_time"; then
        cleanup_problem "could not kill the exact hostile-storage NBD server"
        workspace_removal_safe=0
        return 1
      fi
      server_exit_deadline=$((SECONDS + 2))
      while ! hostile_storage_nbd_server_process_is_gone &&
        ((SECONDS < server_exit_deadline)); do
        sleep 0.02
      done
    fi
    if ! hostile_storage_nbd_server_process_is_gone; then
      cleanup_problem "hostile-storage NBD server remains after exact SIGKILL"
      workspace_removal_safe=0
      return 1
    fi
    hostile_storage_nbd_server_started=0
    hostile_storage_nbd_server_stopped=0
  fi

  fuse_mount_evidence="$(
    awk -v target="$hostile_storage_fuse_mount" '
      {
        separator = 0
        for (field_index = 7; field_index <= NF; field_index++)
          if ($field_index == "-") {
            separator = field_index
            break
          }
        if ($5 != target)
          next
        matches++
        if (separator == 0 || $(separator + 1) != "fuse.bindfs")
          invalid++
      }
      END { printf "%d:%d\n", matches + 0, invalid + 0 }
    ' /proc/self/mountinfo
  )"
  command_status=$?
  if [[ "$command_status" != 0 ||
    ! "$fuse_mount_evidence" =~ ^[0-9]+:[0-9]+$ ||
    ( "$fuse_mount_evidence" != 0:0 &&
      "$fuse_mount_evidence" != 1:0 ) ]]; then
    cleanup_problem \
      "hostile-storage FUSE mount identity is unsafe: ${fuse_mount_evidence:-invalid}"
    workspace_removal_safe=0
    return 1
  fi
  mount_count="${fuse_mount_evidence%%:*}"
  if [[ "$mount_count" == 1 ]]; then
    if [[ "$hostile_storage_fuse_daemon_started" == 1 ]] &&
      ! hostile_storage_fuse_daemon_process_is_gone &&
      ! hostile_storage_fuse_daemon_is_exact; then
      cleanup_problem \
        "hostile-storage FUSE daemon identity changed before unmount"
      workspace_removal_safe=0
      return 1
    fi
    [[ "$hostile_storage_fusermount_executable" == \
      /usr/bin/fusermount ]] || {
      cleanup_problem \
        "refusing an unsafe hostile-storage FUSE unmount executable"
      workspace_removal_safe=0
      return 1
    }
    timeout --signal=TERM --kill-after=2s 5s \
      "$hostile_storage_fusermount_executable" \
      -u "$hostile_storage_fuse_mount"
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not unmount hostile-storage FUSE backing (status $command_status)"
      workspace_removal_safe=0
      return 1
    fi
  fi
  hostile_storage_fuse_mounted=0
  mount_count="$(
    awk -v target="$hostile_storage_fuse_mount" \
      '$5 == target { count++ } END { print count + 0 }' \
      /proc/self/mountinfo
  )"
  command_status=$?
  if [[ "$command_status" != 0 || "$mount_count" != 0 ]]; then
    cleanup_problem \
      "hostile-storage FUSE mount remains: count=${mount_count:-invalid}"
    workspace_removal_safe=0
    return 1
  fi

  if [[ "$hostile_storage_fuse_daemon_started" == 1 ]]; then
    if ! hostile_storage_fuse_daemon_process_is_gone; then
      if ! hostile_storage_fuse_daemon_is_exact; then
        cleanup_problem \
          "hostile-storage FUSE daemon identity changed before cleanup"
        workspace_removal_safe=0
        return 1
      fi
      if ! terminate_exact_background_process \
        "$hostile_storage_fuse_daemon_pid" \
        "$hostile_storage_fuse_daemon_start_time"; then
        cleanup_problem \
          "could not terminate the exact hostile-storage FUSE daemon"
        workspace_removal_safe=0
        return 1
      fi
    fi
    fuse_exit_deadline=$((SECONDS + 5))
    while ! hostile_storage_fuse_daemon_process_is_gone &&
      ((SECONDS < fuse_exit_deadline)); do
      sleep 0.02
    done
    if ! hostile_storage_fuse_daemon_process_is_gone; then
      if ! kill_exact_background_process \
        "$hostile_storage_fuse_daemon_pid" \
        "$hostile_storage_fuse_daemon_start_time"; then
        cleanup_problem \
          "could not kill the exact hostile-storage FUSE daemon"
        workspace_removal_safe=0
        return 1
      fi
      fuse_exit_deadline=$((SECONDS + 2))
      while ! hostile_storage_fuse_daemon_process_is_gone &&
        ((SECONDS < fuse_exit_deadline)); do
        sleep 0.02
      done
    fi
    if ! hostile_storage_fuse_daemon_process_is_gone; then
      cleanup_problem \
        "hostile-storage FUSE daemon remains after exact SIGKILL"
      workspace_removal_safe=0
      return 1
    fi
    hostile_storage_fuse_daemon_started=0
    hostile_storage_fuse_daemon_stopped=0
  fi

  if [[ "$hostile_storage_fuse_connection" =~ ^[0-9]+$ &&
    -e "/sys/fs/fuse/connections/$hostile_storage_fuse_connection" ]]; then
    cleanup_problem \
      "hostile-storage FUSE connection remains after exact teardown"
    workspace_removal_safe=0
    return 1
  fi
  connection_count="$(
    find /sys/fs/fuse/connections -mindepth 1 -maxdepth 1 \
      -type d -printf . | wc -c
  )"
  command_status=$?
  if [[ "$command_status" != 0 || ! "$connection_count" =~ ^[0-9]+$ ||
    "$connection_count" != 0 ]]; then
    cleanup_problem \
      "FUSE connections remain after hostile-storage teardown: ${connection_count:-invalid}"
    workspace_removal_safe=0
    return 1
  fi
  hostile_storage_fuse_connection=
  if [[ "$hostile_storage_fuse_control_mounted" == 1 ]]; then
    sudo umount -- /sys/fs/fuse/connections
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not unmount the test-owned FUSE control filesystem (status $command_status)"
      workspace_removal_safe=0
      return 1
    fi
    hostile_storage_fuse_control_mounted=0
    if [[ "$(findmnt -n -o FSTYPE -- /sys/fs/fuse/connections 2>/dev/null)" == \
      fusectl ]]; then
      cleanup_problem "test-owned FUSE control filesystem remains mounted"
      workspace_removal_safe=0
      return 1
    fi
  fi
}

cleanup_public_port_is_unbound() {
  local listener_count
  local command_status

  listener_count="$(
    sudo ss -H -ltn 'sport = :39777' |
      awk 'END { print NR + 0 }'
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not inspect TCP port 39777 before destructive cleanup (status $command_status)"
    return 1
  fi
  if [[ ! "$listener_count" =~ ^[0-9]+$ ]]; then
    cleanup_problem \
      "received an invalid TCP port 39777 listener count: ${listener_count:-empty}"
    return 1
  fi
  if [[ "$listener_count" != 0 ]]; then
    cleanup_problem \
      "TCP port 39777 remains bound by $listener_count listener(s)"
    sudo ss -H -ltnp 'sport = :39777' >&2 || true
    return 1
  fi
  return 0
}

cleanup() {
  status=$?
  cleanup_failed=0
  workspace_removal_safe=1
  cleanup_state_safe=1
  declare -A cleanup_control_groups=()
  trap - EXIT
  set +e

  if ! resume_hostile_storage_for_cleanup; then
    cleanup_problem \
      "could not resume the exact FUSE/NBD hostile-storage stack; the disposable VM must be terminated"
    exit 1
  fi
  cleanup_cgroup_memory_sampler
  cleanup_hostile_storage_clients
  cleanup_background_downloads
  for unit in "$socket_unit" "$service_unit" "$sentinel_unit"; do
    cleanup_control_groups["$unit"]="$(
      sudo systemctl show --property=ControlGroup --value "$unit"
    )"
    command_status=$?
    if [[ "$command_status" != 0 ]]; then
      cleanup_problem \
        "could not record $unit cgroup before stopping it (status $command_status)"
      cleanup_state_safe=0
      cleanup_control_groups["$unit"]=
    fi
  done
  for unit in "$socket_unit" "$service_unit" "$sentinel_unit"; do
    if ! cleanup_stop_unit "$unit"; then
      cleanup_state_safe=0
    fi
  done
  for unit in "$socket_unit" "$service_unit" "$sentinel_unit"; do
    if ! cleanup_unit_cgroup_is_empty \
      "$unit" "${cleanup_control_groups[$unit]}"; then
      cleanup_state_safe=0
    fi
  done
  if ! cleanup_public_port_is_unbound; then
    cleanup_state_safe=0
  fi
  if [[ "$cleanup_state_safe" != 1 ]]; then
    cleanup_problem \
      "retaining units, mounts, workspace, and account because stopped state, empty cgroups, and an unbound TCP port were not all proven"
    exit 1
  fi

  for unit_path in \
    "$override_path" \
    "$socket_override_path" \
    "$service_path" \
    "$socket_path"
  do
    if [[ -e "$unit_path" || -L "$unit_path" ]]; then
      sudo rm -f -- "$unit_path"
      command_status=$?
      if [[ "$command_status" != 0 ]]; then
        cleanup_problem \
          "could not remove unit path $unit_path (status $command_status)"
      fi
    fi
    if [[ -e "$unit_path" || -L "$unit_path" ]]; then
      cleanup_problem "unit path remains after cleanup: $unit_path"
    fi
  done

  for drop_in_dir in "$override_dir" "$socket_override_dir"; do
    if [[ -e "$drop_in_dir" || -L "$drop_in_dir" ]]; then
      sudo rmdir -- "$drop_in_dir"
      command_status=$?
      if [[ "$command_status" != 0 ]]; then
        cleanup_problem \
          "could not remove drop-in directory $drop_in_dir (status $command_status)"
      fi
    fi
    if [[ -e "$drop_in_dir" || -L "$drop_in_dir" ]]; then
      cleanup_problem "drop-in directory remains after cleanup: $drop_in_dir"
    fi
  done

  sudo systemctl daemon-reload >/dev/null
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem "systemctl daemon-reload failed (status $command_status)"
  fi

  for unit in "$socket_unit" "$service_unit" "$sentinel_unit"; do
    cleanup_reset_failed_unit "$unit"
    cleanup_verify_unit_inactive "$unit"
  done

  if [[ "$host_shm_sentinel_created" == 1 ]]; then
    if [[ ! "$host_shm_sentinel" =~ ^/dev/shm/recasaos-public-files-ci-[0-9]+-[0-9]+\.[A-Za-z0-9]{6}$ ]]; then
      cleanup_problem \
        "refusing unsafe shared-memory sentinel cleanup: $host_shm_sentinel"
    else
      sudo rm -f -- "$host_shm_sentinel"
      command_status=$?
      if [[ "$command_status" != 0 ]]; then
        cleanup_problem \
          "could not remove shared-memory sentinel (status $command_status)"
      fi
      if [[ -e "$host_shm_sentinel" || -L "$host_shm_sentinel" ]]; then
        cleanup_problem \
          "shared-memory sentinel remains after cleanup: $host_shm_sentinel"
      fi
    fi
  fi

  if [[ "$nested_mount_cleanup_required" == 1 ]]; then
    nested_mount_count="$(
      awk -v target="$nested_mount" '
        $5 == target { count++ }
        END { print count + 0 }
      ' /proc/self/mountinfo
    )"
    command_status=$?
    if [[ "$command_status" != 0 ||
      ! "$nested_mount_count" =~ ^[0-9]+$ ]]; then
      cleanup_problem \
        "could not determine nested mount count (status $command_status)"
      workspace_removal_safe=0
    elif [[ "$nested_mount_count" -gt 1 ]]; then
      cleanup_problem \
        "nested mount has ambiguous mountinfo count: $nested_mount_count"
      workspace_removal_safe=0
    elif [[ "$nested_mount_count" == 1 ]]; then
      sudo umount -- "$nested_mount"
      command_status=$?
      if [[ "$command_status" != 0 ]]; then
        cleanup_problem \
          "could not unmount $nested_mount (status $command_status)"
        workspace_removal_safe=0
      else
        nested_mount_count="$(
          awk -v target="$nested_mount" '
            $5 == target { count++ }
            END { print count + 0 }
          ' /proc/self/mountinfo
        )"
        command_status=$?
        if [[ "$command_status" != 0 ||
          "$nested_mount_count" != 0 ]]; then
          cleanup_problem \
            "nested mount remains after cleanup: count=${nested_mount_count:-invalid} status=$command_status"
          workspace_removal_safe=0
        fi
      fi
    fi
  fi

  cleanup_hostile_storage_stack

  if [[ "$workspace_removal_safe" == 1 ]]; then
    if [[ -e "$workspace" || -L "$workspace" ]]; then
      sudo rm -rf -- "$workspace"
      command_status=$?
      if [[ "$command_status" != 0 ]]; then
        cleanup_problem \
          "could not remove workspace $workspace (status $command_status)"
      fi
    fi
    if [[ -e "$workspace" || -L "$workspace" ]]; then
      cleanup_problem "workspace remains after cleanup: $workspace"
    fi
  else
    cleanup_problem "retained workspace because mount cleanup is unsafe: $workspace"
  fi

  if [[ "$account_cleanup_authorized" == 1 ]]; then
    cleanup_account_entry passwd userdel user
    cleanup_account_entry group groupdel group
  fi

  if [[ "$status" == 0 && "$cleanup_failed" != 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

"$repo_root/deploy/systemd/check-public-files-units.sh" "$repo_root"

print_wait_timeout_diagnostics() {
  local description=$1

  if [[ "$description" == "public portal activation" ]]; then
    printf '%s\n' 'public-files activation diagnostics:' >&2
    sudo systemctl show \
      --property=LoadState \
      --property=ActiveState \
      --property=SubState \
      --property=Result \
      --property=ConditionResult \
      --property=MainPID \
      --property=ExecMainCode \
      --property=ExecMainStatus \
      --property=NRestarts \
      "$socket_unit" "$service_unit" >&2 || true
    sudo systemctl status --no-pager --full \
      "$socket_unit" "$service_unit" >&2 || true
    sudo journalctl --no-pager --output=short-monotonic --lines=120 \
      --unit="$socket_unit" --unit="$service_unit" >&2 || true
    sudo ss -H -ltnp 'sport = :39777' >&2 || true
  fi
  case "$description" in
    *storage\ worker* | *active\ worker* | *slow\ download*)
      print_storage_worker_diagnostics
      ;;
  esac
}

wait_until() {
  local attempt
  local attempt_limit=150
  local description=$1

  shift
  if [[ "$description" == "public service restart after SIGKILL" ]]; then
    attempt_limit=300
  fi
  for ((attempt = 0; attempt < attempt_limit; attempt++)); do
    if "$@"; then
      return 0
    fi
    sleep 0.1
  done
  print_wait_timeout_diagnostics "$description"
  fail "timed out waiting for ${description}"
}

wait_until_before() {
  local deadline=$2
  local description=$1

  [[ "$deadline" =~ ^[0-9]+$ ]] ||
    fail "invalid wait deadline for $description"
  shift 2
  while ((SECONDS < deadline)); do
    if "$@"; then
      return 0
    fi
    sleep 0.1
  done
  print_wait_timeout_diagnostics "$description"
  fail "timed out waiting for ${description}"
}

require_unit_property() {
  unit=$1
  property=$2
  expected=$3
  actual="$(sudo systemctl show --property="$property" --value "$unit")"
  [[ "$actual" == "$expected" ]] ||
    fail "$unit property $property is $actual, want $expected"
}

assert_service_cgroup_limits() {
  local control_group
  local cgroup_path
  local controllers
  local memory_max
  local memory_swap_max
  local pids_max

  control_group="$(
    sudo systemctl show --property=ControlGroup --value "$service_unit"
  )"
  [[ "$control_group" == "/system.slice/$service_unit" ]] ||
    fail "service is in unexpected cgroup: $control_group"
  cgroup_path="/sys/fs/cgroup${control_group}"
  [[ -f "$cgroup_path/cgroup.controllers" ]] ||
    fail "service cgroup has no v2 controller file"
  controllers=" $(<"$cgroup_path/cgroup.controllers") "
  [[ "$controllers" == *" memory "* ]] ||
    fail "memory controller is unavailable to the service cgroup"
  [[ "$controllers" == *" pids "* ]] ||
    fail "pids controller is unavailable to the service cgroup"
  memory_max="$(<"$cgroup_path/memory.max")"
  memory_swap_max="$(<"$cgroup_path/memory.swap.max")"
  pids_max="$(<"$cgroup_path/pids.max")"
  [[ "$memory_max" == 536870912 ]] ||
    fail "effective memory.max is $memory_max, want 536870912"
  [[ "$memory_swap_max" == 0 ]] ||
    fail "effective memory.swap.max is $memory_swap_max, want 0"
  [[ "$pids_max" == 256 ]] ||
    fail "effective pids.max is $pids_max, want 256"
}

assert_systemd_credential_for_pid() {
  local pid=$1
  local credential_path
  local credential_metadata
  local credential_uid
  local credential_gid
  local credential_mode
  local credential_links
  local credential_size
  local credential_acl
  local expected_acl
  local credential_layout
  local credential_mount
  local mount_evidence

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] ||
    fail "cannot inspect credential for unsafe service PID: $pid"
  sudo test -d "/proc/$pid" ||
    fail "service PID disappeared before credential inspection: $pid"

  credential_path="/proc/$pid/root/run/credentials/$service_unit/recasaos-public-file-verifier"
  sudo test -f "$credential_path" ||
    fail "systemd credential is not a regular file in the service root"
  sudo test ! -L "$credential_path" ||
    fail "systemd credential is a symbolic link in the service root"

  credential_mount="/run/credentials/$service_unit"
  mount_evidence="$(
    sudo awk -v target="$credential_mount" '
      $5 == target {
        count++
        options = "," $6 ","
        if (options ~ /,ro,/)
          read_only++
      }
      END {
        printf "%d:%d", count + 0, read_only + 0
      }
    ' "/proc/$pid/mountinfo"
  )"
  [[ "$mount_evidence" == 1:1 ]] ||
    fail "systemd credential store is not one read-only mount: $mount_evidence"

  credential_metadata="$(
    sudo stat -c '%u:%g:%a:%h:%s' "$credential_path"
  )"
  IFS=: read -r \
    credential_uid \
    credential_gid \
    credential_mode \
    credential_links \
    credential_size \
    <<<"$credential_metadata"
  credential_acl="$(
    sudo getfacl --absolute-names --numeric --omit-header -- \
      "$credential_path"
  )"

  if [[ "$credential_uid" == 0 &&
    "$credential_gid" == 0 &&
    "$credential_mode" == 440 &&
    "$credential_links" == 1 &&
    "$credential_size" == 100 ]]; then
    printf -v expected_acl \
      'user::r--\nuser:%s:r--\ngroup::---\nmask::r--\nother::---' \
      "$service_uid"
    credential_layout=root-owned-named-user-acl
  elif [[ "$credential_uid" == "$service_uid" &&
    ( "$credential_gid" == 0 || "$credential_gid" == "$service_gid" ) &&
    "$credential_mode" == 400 &&
    "$credential_links" == 1 &&
    "$credential_size" == 100 ]]; then
    printf -v expected_acl 'user::r--\ngroup::---\nother::---'
    credential_layout=service-owned-read-only-fallback
  else
    fail "systemd credential metadata is unsafe: $credential_metadata"
  fi

  [[ "$credential_acl" == "$expected_acl" ]] ||
    fail "systemd credential access ACL is unsafe for $credential_metadata"
  printf 'verified systemd credential layout: %s (%s)\n' \
    "$credential_layout" "$credential_metadata"
}

assert_service_api_vfs_isolation() {
  local pid=$1
  local dev_shm_mode
  local temporary_path

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] ||
    fail "cannot inspect API VFS isolation for unsafe service PID: $pid"
  sudo test -d "/proc/$pid" ||
    fail "service PID disappeared before API VFS inspection: $pid"

  sudo test ! -e "/proc/$pid/root/sys/kernel" ||
    fail "host sysfs kernel tree is visible in the service root"
  sudo test ! -e "/proc/$pid/root/sys/class" ||
    fail "host sysfs class tree is visible in the service root"
  if sudo awk '
    $5 == "/sys" {
      for (field = 1; field <= NF; field++)
        if ($field == "-" && $(field + 1) == "sysfs")
          found = 1
    }
    END { exit found ? 0 : 1 }
  ' "/proc/$pid/mountinfo"; then
    fail "a sysfs filesystem is mounted at /sys in the service namespace"
  fi

  sudo test ! -e "/proc/$pid/root/proc/sys" ||
    fail "non-process procfs APIs are visible in the service root"
  sudo test ! -e "/proc/$pid/root$host_shm_sentinel" ||
    fail "host shared-memory contents are visible in the service root"
  dev_shm_mode="$(sudo stat -Lc %a "/proc/$pid/root/dev/shm")"
  [[ "$dev_shm_mode" == 0 ]] ||
    fail "service /dev/shm mode is $dev_shm_mode, want inaccessible mode 0"

  for temporary_path in tmp var/tmp; do
    sudo test -d "/proc/$pid/root/$temporary_path" ||
      fail "service /$temporary_path directory is missing"
    if sudo touch "/proc/$pid/root/$temporary_path/forbidden" 2>/dev/null; then
      fail "service /$temporary_path is writable"
    fi
  done
}

socket_is_inactive_and_unbound() {
  if sudo systemctl is-active --quiet "$socket_unit"; then
    return 1
  fi
  [[ "$(
    sudo ss -H -ltn |
      awk '$4 == "127.0.0.1:39777" { count++ } END { print count + 0 }'
  )" == 0 ]]
}

assert_unsafe_verifier_skips_units() {
  local description=$1
  local unit
  local condition_result
  local active_state
  local main_pid

  for unit in "$service_unit" "$socket_unit"; do
    sudo systemctl start "$unit" ||
      fail "$description did not skip $unit cleanly"
    condition_result="$(
      sudo systemctl show --property=ConditionResult --value "$unit"
    )"
    active_state="$(
      sudo systemctl show --property=ActiveState --value "$unit"
    )"
    [[ "$condition_result" == no ]] ||
      fail "$description left $unit ConditionResult=$condition_result"
    [[ "$active_state" == inactive ]] ||
      fail "$description left $unit ActiveState=$active_state"
    if sudo systemctl is-failed --quiet "$unit"; then
      fail "$description moved $unit into the failed state"
    fi
  done
  main_pid="$(
    sudo systemctl show --property=MainPID --value "$service_unit"
  )"
  [[ "$main_pid" == 0 ]] ||
    fail "$description started a service process: $main_pid"
  wait_until "$description listener check" socket_is_inactive_and_unbound
}

page_is_ready() {
  [[ "$(
    curl -q -sS --max-time 1 -o /dev/null -w '%{http_code}' \
      http://127.0.0.1:39777/public-files/ 2>/dev/null || true
  )" == 200 ]]
}

activate_public_binary() {
  local binary=$1
  local description=$2
  local previous_invocation
  local previous_pid
  local next_invocation
  local next_pid
  local stopped_pid
  local stopped_state

  [[ "$binary" == "$production_binary" ||
    "$binary" == "$systemd_test_binary" ]] ||
    fail "refusing unreviewed portal binary path: $binary"
  [[ -f "$binary" && ! -L "$binary" && -x "$binary" ]] ||
    fail "portal binary is unsafe before $description"
  previous_pid="${portal_pid:-0}"
  previous_invocation="$(
    sudo systemctl show --property=InvocationID --value "$service_unit"
  )"

  sudo systemctl stop "$socket_unit" "$service_unit"
  stopped_state="$(
    sudo systemctl show --property=ActiveState --value "$service_unit"
  )"
  stopped_pid="$(
    sudo systemctl show --property=MainPID --value "$service_unit"
  )"
  [[ "$stopped_state" == inactive && "$stopped_pid" == 0 ]] ||
    fail "service did not fully stop before $description"
  wait_until "$description stopped listener" socket_is_inactive_and_unbound
  sudo install -o root -g root -m 0755 \
    "$binary" "$rootfs/usr/bin/recasaos-public-files"
  sudo cmp -s -- "$binary" "$rootfs/usr/bin/recasaos-public-files" ||
    fail "installed portal bytes differ before $description"
  sudo systemctl start "$socket_unit"
  wait_until "public portal activation" page_is_ready

  next_pid="$(
    sudo systemctl show --property=MainPID --value "$service_unit"
  )"
  next_invocation="$(
    sudo systemctl show --property=InvocationID --value "$service_unit"
  )"
  [[ "$next_pid" =~ ^[0-9]+$ && "$next_pid" -gt 1 ]] ||
    fail "$description produced no service process"
  [[ "$next_pid" != "$previous_pid" ]] ||
    fail "$description reused the previous service PID"
  [[ -n "$next_invocation" && "$next_invocation" != "$previous_invocation" ]] ||
    fail "$description did not create a new service invocation"
  portal_pid=$next_pid
  portal_invocation=$next_invocation

  assert_service_cgroup_limits
  assert_systemd_credential_for_pid "$portal_pid"
  assert_service_api_vfs_isolation "$portal_pid"
  wait_until "unchanged management sentinel after $description" \
    sentinel_is_unchanged
}

service_is_failed() {
  sudo systemctl is-failed --quiet "$service_unit"
}

service_has_new_pid() {
  local current_invocation
  local current_pid

  current_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"
  current_invocation="$(
    sudo systemctl show --property=InvocationID --value "$service_unit"
  )"
  [[ "$current_pid" =~ ^[0-9]+$ && "$current_pid" -gt 1 &&
    "$current_pid" != "$portal_pid" &&
    -n "$current_invocation" &&
    "$current_invocation" != "$portal_invocation" ]]
}

storage_worker_pids() {
  local command_status
  local pids

  if pids="$(
    sudo pgrep -P "$portal_pid" -f -- \
      '--internal-public-files-storage-worker (list|file)' 2>/dev/null
  )"; then
    printf '%s\n' "$pids"
    return 0
  else
    command_status=$?
  fi
  [[ "$command_status" == 1 ]] ||
    fail "storage worker enumeration failed with status $command_status"
}

storage_worker_count() {
  local pids
  pids="$(storage_worker_pids)"
  if [[ -z "$pids" ]]; then
    printf '0\n'
  else
    printf '%s\n' "$pids" | awk 'NF { count++ } END { print count + 0 }'
  fi
}

slow_download_process_is_live() {
  local expected_start_time=$2
  local process_state
  local pid=$1
  local start_time

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 &&
    "$expected_start_time" =~ ^[0-9]+$ ]] || return 1
  start_time="$(process_start_time "$pid")" || return 1
  [[ "$start_time" == "$expected_start_time" ]] || return 1
  process_state="$(
    ps -o stat= -p "$pid" 2>/dev/null |
      awk 'NR == 1 { print substr($1, 1, 1) }' || true
  )"
  [[ -n "$process_state" && "$process_state" != Z &&
    "$process_state" != X ]]
}

storage_worker_count_is() {
  local expected=$1
  local count
  slow_downloads_are_healthy || return 1
  count="$(storage_worker_count)"
  last_storage_worker_count=$count
  if ((count > max_storage_worker_count)); then
    max_storage_worker_count=$count
  fi
  [[ "$count" == "$expected" ]]
}

storage_workers_are_stopped() {
  local expected=$1
  local count=0
  local process_state
  local worker_pid

  slow_downloads_are_healthy || return 1
  while IFS= read -r worker_pid; do
    [[ "$worker_pid" =~ ^[0-9]+$ && "$worker_pid" -gt 1 ]] ||
      return 1
    process_state="$(
      ps -o stat= -p "$worker_pid" 2>/dev/null |
        awk 'NR == 1 { print substr($1, 1, 1) }' || true
    )"
    [[ "$process_state" == T ]] || return 1
    count=$((count + 1))
  done < <(storage_worker_pids)
  [[ "$count" == "$expected" ]]
}

storage_workers_are_in_d_state() {
  local expected=$1
  local -a worker_pids=()
  local worker_pid

  hostile_storage_clients_are_live || return 1
  mapfile -t worker_pids < <(storage_worker_pids)
  [[ "${#worker_pids[@]}" == "$expected" ]] || return 1
  for worker_pid in "${worker_pids[@]}"; do
    [[ "$worker_pid" =~ ^[0-9]+$ && "$worker_pid" -gt 1 ]] || return 1
  done
  sudo /usr/bin/python3 - "${worker_pids[@]}" <<'D_STATE_PYTHON' \
    >/dev/null 2>&1
from pathlib import Path
import sys


def task_state(stat_path):
    data = stat_path.read_bytes()
    marker = data.rfind(b") ")
    fields = data[marker + 2 :].split() if marker >= 0 else []
    if len(fields) <= 19:
        raise RuntimeError("could not parse worker task identity")
    return fields[0]


for pid_text in sys.argv[1:]:
    if not pid_text.isdecimal() or int(pid_text) <= 1:
        raise SystemExit(1)
    task_root = Path("/proc") / pid_text / "task"
    try:
        tasks = list(task_root.iterdir())
    except FileNotFoundError:
        raise SystemExit(1)
    has_d_state_task = False
    for task in tasks:
        if not task.name.isdecimal():
            continue
        try:
            if task_state(task / "stat") == b"D":
                has_d_state_task = True
                break
        except FileNotFoundError:
            continue
    if not has_d_state_task:
        raise SystemExit(1)
D_STATE_PYTHON
}

assert_hostile_storage_worker_boundaries() {
  local expected_parent=$2
  local phase=$1
  local hostile_worker_index
  local hostile_worker_identity_arguments=()

  [[ "$phase" == blocked || "$phase" == kill-pending ]] ||
    fail "cannot inspect hostile workers in an unsafe phase: $phase"
  [[ "$expected_parent" =~ ^[0-9]+$ && "$expected_parent" -ge 1 ]] ||
    fail "cannot inspect hostile workers for an unsafe parent"
  [[ "${#hostile_worker_pids[@]}" == 4 &&
    "${#hostile_worker_start_times[@]}" == 4 ]] ||
    fail "cannot inspect an incomplete hostile-storage worker set"
  for hostile_worker_index in "${!hostile_worker_pids[@]}"; do
    hostile_worker_identity_arguments+=(
      "${hostile_worker_pids[$hostile_worker_index]}:${hostile_worker_start_times[$hostile_worker_index]}"
    )
  done

  if ! sudo /usr/bin/python3 - \
    "$phase" \
    "$expected_parent" \
    "$service_uid" \
    "$rootfs/usr/bin/recasaos-public-files" \
    "${hostile_worker_identity_arguments[@]}" <<'HOSTILE_PYTHON'
import os
from pathlib import Path
import stat
import sys

phase = sys.argv[1]
expected_parent = int(sys.argv[2])
expected_uid = int(sys.argv[3])
reviewed_binary_path = Path(sys.argv[4])
worker_pairs = sys.argv[5:]

if (
    phase not in {"blocked", "kill-pending"}
    or expected_parent < 1
    or expected_uid < 1
    or not reviewed_binary_path.is_absolute()
    or len(worker_pairs) != 4
):
    raise SystemExit("unsafe hostile-storage worker evidence arguments")

reviewed_binary = os.stat(reviewed_binary_path, follow_symlinks=False)
if (
    not stat.S_ISREG(reviewed_binary.st_mode)
    or reviewed_binary.st_uid != 0
    or reviewed_binary.st_gid != 0
    or stat.S_IMODE(reviewed_binary.st_mode) != 0o755
    or reviewed_binary.st_nlink != 1
):
    raise RuntimeError("reviewed hostile-storage worker image is unsafe")


def read_identity(pid):
    data = (Path("/proc") / str(pid) / "stat").read_bytes()
    marker = data.rfind(b") ")
    fields = data[marker + 2 :].split() if marker >= 0 else []
    if len(fields) <= 19 or not fields[1].isdigit() or not fields[19].isdigit():
        raise RuntimeError("could not parse hostile-storage worker identity")
    return fields[0], int(fields[1]), fields[19]


def read_status(pid):
    values = {}
    for line in (Path("/proc") / str(pid) / "status").read_bytes().splitlines():
        if b":" in line:
            key, value = line.split(b":", 1)
            values[key] = value.strip()
    return values


def read_task_identity(pid, tid):
    data = (Path("/proc") / str(pid) / "task" / str(tid) / "stat").read_bytes()
    marker = data.rfind(b") ")
    fields = data[marker + 2 :].split() if marker >= 0 else []
    if len(fields) <= 19 or not fields[19].isdigit():
        raise RuntimeError("could not parse hostile-storage task identity")
    return fields[0], fields[19]


def find_d_state_task(pid):
    task_root = Path("/proc") / str(pid) / "task"
    candidates = []
    for task in task_root.iterdir():
        if not task.name.isdecimal():
            continue
        tid = int(task.name)
        try:
            task_state, task_start = read_task_identity(pid, tid)
        except FileNotFoundError:
            continue
        if task_state == b"D":
            candidates.append((tid, task_start))
    if not candidates:
        raise RuntimeError(
            f"hostile-storage worker {pid} has no D-state task"
        )
    return min(candidates)


seen = set()
d_tasks = []
kill_bit = 1 << (9 - 1)
for pair in worker_pairs:
    pid_text, separator, expected_start = pair.partition(":")
    if (
        separator != ":"
        or not pid_text.isdecimal()
        or not expected_start.isdecimal()
    ):
        raise RuntimeError("malformed hostile-storage worker identity")
    pid = int(pid_text)
    if pid <= 1 or pid in seen:
        raise RuntimeError("unsafe or duplicate hostile-storage worker PID")
    seen.add(pid)

    state, parent, start_before = read_identity(pid)
    if start_before.decode("ascii") != expected_start:
        raise RuntimeError("hostile-storage worker identity changed")
    if parent != expected_parent:
        raise RuntimeError(
            f"hostile-storage worker {pid} parent is {parent}, "
            f"want {expected_parent}"
        )
    d_tid, d_start_before = find_d_state_task(pid)
    d_tasks.append(f"{pid}:{d_tid}")

    try:
        worker_executable = os.stat(Path("/proc") / str(pid) / "exe")
    except FileNotFoundError:
        # After a group-wide SIGKILL, Linux can tear down the thread-group
        # leader's executable while a sibling task remains blocked in D-state.
        # The blocked phase already proved the image, and this phase still
        # proves the recorded PID/start time, D-state task, credentials, and
        # pending SIGKILL before accepting that narrow kernel state.
        if phase != "kill-pending":
            raise RuntimeError(
                f"hostile-storage worker {pid} image disappeared before cancellation"
            ) from None
    else:
        if (
            worker_executable.st_dev != reviewed_binary.st_dev
            or worker_executable.st_ino != reviewed_binary.st_ino
        ):
            raise RuntimeError("hostile-storage worker image identity changed")

    status = read_status(pid)
    user_ids = status.get(b"Uid", b"").split()
    if user_ids != [str(expected_uid).encode("ascii")] * 4:
        raise RuntimeError("hostile-storage worker UID boundary changed")
    if status.get(b"CapEff") != b"0000000000000000":
        raise RuntimeError("hostile-storage worker retained an effective capability")
    pending_values = []
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

    state_after, parent_after, start_after = read_identity(pid)
    if (
        parent_after != expected_parent
        or start_after != start_before
    ):
        raise RuntimeError("hostile-storage worker changed during inspection")
    d_state_after, d_start_after = read_task_identity(pid, d_tid)
    if d_state_after != b"D" or d_start_after != d_start_before:
        raise RuntimeError("hostile-storage D-state task changed during inspection")

print(
    "hostile-storage worker evidence: "
    f"phase={phase} parent={expected_parent} count={len(seen)} "
    f"state=D tasks={','.join(d_tasks)}"
)
HOSTILE_PYTHON
  then
    fail "hostile-storage worker evidence failed"
  fi
}

hostile_storage_clients_are_live() {
  local client_index

  [[ "${#hostile_storage_clients[@]}" == 4 &&
    "${#hostile_storage_client_start_times[@]}" == 4 ]] || return 1
  for client_index in "${!hostile_storage_clients[@]}"; do
    slow_download_process_is_live \
      "${hostile_storage_clients[$client_index]}" \
      "${hostile_storage_client_start_times[$client_index]}" || return 1
  done
}

hostile_storage_clients_are_complete() {
  local client_index

  [[ "${#hostile_storage_clients[@]}" == 4 ]] || return 1
  for client_index in "${!hostile_storage_clients[@]}"; do
    if slow_download_process_is_live \
      "${hostile_storage_clients[$client_index]}" \
      "${hostile_storage_client_start_times[$client_index]}"; then
      return 1
    fi
  done
}

start_hostile_storage_client() {
  local failure_file
  local pid
  local prefix
  local start_time

  hostile_storage_client_sequence=$((hostile_storage_client_sequence + 1))
  prefix="${workspace}/hostile-client-${hostile_storage_client_sequence}"
  [[ "$prefix" == \
    "$workspace/hostile-client-$hostile_storage_client_sequence" ]] ||
    fail "refusing unsafe hostile-storage client prefix: $prefix"
  for suffix in headers body status failure; do
    [[ ! -e "$prefix.$suffix" && ! -L "$prefix.$suffix" ]] ||
      fail "hostile-storage client state path already exists: $prefix.$suffix"
    install -m 0600 /dev/null "$prefix.$suffix"
  done
  failure_file="$prefix.failure"

  printf 'Authorization: Bearer %s\n' "$test_bearer" |
    curl -q -sS \
      --connect-timeout 2 \
      --max-time 25 \
      -H @- \
      -H 'Connection: close' \
      -D "$prefix.headers" \
      -o "$prefix.body" \
      -w '%{http_code}\n' \
      'http://127.0.0.1:39777/public-files/api/list?path=' \
      >"$prefix.status" 2>"$failure_file" &
  pid=$!
  start_time="$(process_start_time "$pid")" || {
    wait "$pid" 2>/dev/null || true
    fail "hostile-storage client exited before identity capture"
  }
  hostile_storage_clients+=("$pid")
  hostile_storage_client_start_times+=("$start_time")
  hostile_storage_client_prefixes+=("$prefix")
}

assert_hostile_storage_client_responses() {
  local client_index
  local prefix
  local retry_after_evidence

  [[ "${#hostile_storage_clients[@]}" == 4 &&
    "${#hostile_storage_client_prefixes[@]}" == 4 ]] ||
    fail "cannot validate an incomplete hostile-storage client set"
  for client_index in "${!hostile_storage_clients[@]}"; do
    prefix="${hostile_storage_client_prefixes[$client_index]}"
    if ! wait "${hostile_storage_clients[$client_index]}"; then
      sed -n '1,20p' "$prefix.failure" >&2
      fail "hostile-storage client exited unsuccessfully"
    fi
    [[ "$(<"$prefix.status")" == 503 ]] ||
      fail "hostile-storage timeout did not return 503"
    [[ "$(<"$prefix.body")" == \
      '{"error":"storage capacity unavailable"}' ]] ||
      fail "hostile-storage timeout returned an unexpected body"
    retry_after_evidence="$(
      awk '
        {
          line = $0
          sub(/\r$/, "", line)
          separator = index(line, ":")
          if (separator == 0)
            next
          name = tolower(substr(line, 1, separator - 1))
          if (name != "retry-after")
            next
          count++
          value = substr(line, separator + 1)
          sub(/^[[:space:]]+/, "", value)
          sub(/[[:space:]]+$/, "", value)
          if (value != "5")
            invalid++
        }
        END { printf "%d:%d\n", count + 0, invalid + 0 }
      ' "$prefix.headers"
    )"
    [[ "$retry_after_evidence" == 1:0 ]] ||
      fail "hostile-storage timeout lacked one exact Retry-After value 5"
    if grep -aFq -- 'rc1_' \
      "$prefix.headers" "$prefix.body" "$prefix.status" "$prefix.failure"; then
      fail "hostile-storage client diagnostics retained a bearer-shaped value"
    fi
  done
  hostile_storage_clients=()
  hostile_storage_client_start_times=()
  hostile_storage_client_prefixes=()
}

assert_storage_worker_address_space_limit() {
  local build_label=$3
  local expected_start_time=$2
  local worker_pid=$1

  [[ "$worker_pid" =~ ^[0-9]+$ && "$worker_pid" -gt 1 &&
    "$expected_start_time" =~ ^[0-9]+$ ]] ||
    fail "cannot inspect unsafe storage worker identity"
  [[ "$build_label" == production || "$build_label" == systemd-test ]] ||
    fail "cannot inspect storage worker with unsafe build label"
  sudo /usr/bin/python3 - \
    "$worker_pid" \
    "$expected_start_time" \
    "$portal_pid" \
    "$build_label" \
    "$storage_worker_address_space_ceiling" \
    "$storage_worker_address_space_minimum_reserve" <<'PYTHON'
import os
from pathlib import Path
import re
import sys

pid = int(sys.argv[1])
expected_start = sys.argv[2].encode("ascii")
expected_parent = int(sys.argv[3])
build_label = sys.argv[4]
ceiling = int(sys.argv[5])
minimum_reserve = int(sys.argv[6])

if (
    pid <= 1
    or expected_parent <= 1
    or build_label not in {"production", "systemd-test"}
    or ceiling != 2 * 1024 * 1024 * 1024
    or minimum_reserve != 128 * 1024 * 1024
):
    raise SystemExit("unsafe address-space evidence arguments")

proc = Path(f"/proc/{pid}")
portal_proc = Path(f"/proc/{expected_parent}")
expected_command = (
    b"/proc/self/exe\0"
    b"--internal-public-files-storage-worker\0"
    b"file\0"
)


def identity():
    stat_data = (proc / "stat").read_bytes()
    marker = stat_data.rfind(b") ")
    fields = stat_data[marker + 2:].split() if marker >= 0 else []
    if len(fields) <= 19 or not fields[19].isdigit():
        raise RuntimeError("could not parse storage worker start time")
    status = (proc / "status").read_text(encoding="ascii")
    parents = re.findall(r"^PPid:\s*([0-9]+)\s*$", status, re.MULTILINE)
    if len(parents) != 1:
        raise RuntimeError("could not parse storage worker parent")
    return fields[19], int(parents[0]), (proc / "cmdline").read_bytes(), status


start_before, parent_before, command_before, _ = identity()
if (
    start_before != expected_start
    or parent_before != expected_parent
    or command_before != expected_command
):
    raise RuntimeError("storage worker identity changed before limit inspection")

worker_executable = os.stat(proc / "exe")
portal_executable = os.stat(portal_proc / "exe")
if (
    worker_executable.st_dev != portal_executable.st_dev
    or worker_executable.st_ino != portal_executable.st_ino
):
    raise RuntimeError("storage worker does not share the reviewed portal image")

address_limits = []
for line in (proc / "limits").read_text(encoding="ascii").splitlines():
    fields = line.split()
    if fields[:3] == ["Max", "address", "space"]:
        if (
            len(fields) != 6
            or fields[5] != "bytes"
            or not fields[3].isdigit()
            or not fields[4].isdigit()
        ):
            raise RuntimeError("storage worker address-space limit is malformed")
        address_limits.append((int(fields[3]), int(fields[4])))
if len(address_limits) != 1:
    raise RuntimeError("could not parse one storage worker address-space limit")
soft, hard = address_limits[0]

start_after, parent_after, command_after, status_after = identity()
if (
    start_after != start_before
    or parent_after != parent_before
    or command_after != command_before
):
    raise RuntimeError("storage worker identity changed during limit inspection")

vm_sizes = re.findall(
    r"^VmSize:\s*([0-9]+)\s+kB\s*$",
    status_after,
    re.MULTILINE,
)
if len(vm_sizes) != 1:
    raise RuntimeError("could not parse one storage worker VmSize")
vm_size_kib = int(vm_sizes[0])
if vm_size_kib <= 0 or vm_size_kib > ceiling // 1024:
    raise RuntimeError("storage worker VmSize is outside the reviewed ceiling")
vm_size_bytes = vm_size_kib * 1024
if soft != hard or soft <= vm_size_bytes or soft > ceiling:
    raise RuntimeError("storage worker address-space limit is unsafe")
reserve = soft - vm_size_bytes
if reserve < minimum_reserve:
    raise RuntimeError("storage worker address-space reserve is too small")

print(
    "storage worker address-space evidence: "
    f"build={build_label} pid={pid} vm-size-kib={vm_size_kib} "
    f"soft-bytes={soft} hard-bytes={hard} reserve-bytes={reserve}"
)
PYTHON
}

assert_bounded_storage_worker_runtime_boundaries() {
  local index
  local worker_identity_arguments=()

  [[ "${#bounded_worker_pids[@]}" == 8 &&
    "${#bounded_worker_start_times[@]}" == 8 ]] ||
    fail "cannot inspect an incomplete bounded worker set"
  [[ "$portal_pid" =~ ^[0-9]+$ && "$portal_pid" -gt 1 ]] ||
    fail "cannot inspect bounded workers for an unsafe portal identity"
  [[ "$listener_inode" =~ ^[0-9]+$ ]] ||
    fail "cannot inspect bounded workers for an unsafe listener inode"
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] ||
    fail "cannot inspect bounded workers with an unsafe bearer digest"

  for index in "${!bounded_worker_pids[@]}"; do
    worker_identity_arguments+=(
      "${bounded_worker_pids[$index]}:${bounded_worker_start_times[$index]}"
    )
  done

  # One root process takes the same before/after identity snapshots and checks
  # every stopped worker. Spawning dozens of sudo helpers under QEMU TCG would
  # measure the observer rather than the service and can outlive the unchanged
  # production write deadline.
  if ! sudo /usr/bin/python3 - \
    "$portal_pid" \
    "$listener_inode" \
    "$storage_worker_address_space_ceiling" \
    "$storage_worker_address_space_minimum_reserve" \
    "${#test_bearer}" \
    "$digest" \
    "${worker_identity_arguments[@]}" <<'BOUNDED_PYTHON'
import hashlib
import os
from pathlib import Path
import re
import sys

expected_parent = int(sys.argv[1])
listener_inode = sys.argv[2]
ceiling = int(sys.argv[3])
minimum_reserve = int(sys.argv[4])
secret_length = int(sys.argv[5])
secret_digest = sys.argv[6]
worker_pairs = sys.argv[7:]

if (
    expected_parent <= 1
    or not listener_inode.isdigit()
    or ceiling != 2 * 1024 * 1024 * 1024
    or minimum_reserve != 128 * 1024 * 1024
    or secret_length <= 0
    or secret_length > 4096
    or re.fullmatch(r"[0-9a-f]{64}", secret_digest) is None
    or len(worker_pairs) != 8
    or getattr(os, "O_CLOEXEC", 0) != 0o2000000
):
    raise SystemExit("unsafe bounded worker evidence arguments")

expected_command = (
    b"/proc/self/exe\0"
    b"--internal-public-files-storage-worker\0"
    b"file\0"
)
listener_target = f"socket:[{listener_inode}]"
portal_executable = os.stat(f"/proc/{expected_parent}/exe")


def contains_secret(data):
    if len(data) < secret_length:
        return False
    for offset in range(len(data) - secret_length + 1):
        candidate = data[offset : offset + secret_length]
        if hashlib.sha256(candidate).hexdigest() == secret_digest:
            return True
    return False


def identity(proc):
    stat_data = (proc / "stat").read_bytes()
    marker = stat_data.rfind(b") ")
    fields = stat_data[marker + 2 :].split() if marker >= 0 else []
    if (
        len(fields) <= 19
        or fields[0] != b"T"
        or not fields[1].isdigit()
        or not fields[19].isdigit()
    ):
        raise RuntimeError("could not parse one stopped worker identity")
    return fields[19], int(fields[1]), (proc / "cmdline").read_bytes()


seen_pids = set()
for pair in worker_pairs:
    match = re.fullmatch(r"([1-9][0-9]*):([1-9][0-9]*)", pair)
    if match is None:
        raise RuntimeError("malformed bounded worker identity")
    pid = int(match.group(1))
    expected_start = match.group(2).encode("ascii")
    if pid <= 1 or pid in seen_pids:
        raise RuntimeError("unsafe or duplicate bounded worker PID")
    seen_pids.add(pid)
    proc = Path(f"/proc/{pid}")

    start_before, parent_before, command_before = identity(proc)
    if (
        start_before != expected_start
        or parent_before != expected_parent
        or command_before != expected_command
    ):
        raise RuntimeError("bounded worker identity changed before inspection")

    worker_executable = os.stat(proc / "exe")
    if (
        worker_executable.st_dev != portal_executable.st_dev
        or worker_executable.st_ino != portal_executable.st_ino
    ):
        raise RuntimeError("bounded worker does not share the reviewed image")

    limits = (proc / "limits").read_text(encoding="ascii")
    address_limits = []
    for line in limits.splitlines():
        fields = line.split()
        if fields[:3] == ["Max", "address", "space"]:
            if (
                len(fields) != 6
                or fields[5] != "bytes"
                or not fields[3].isdigit()
                or not fields[4].isdigit()
            ):
                raise RuntimeError("bounded worker address limit is malformed")
            address_limits.append((int(fields[3]), int(fields[4])))
    if len(address_limits) != 1:
        raise RuntimeError("could not parse one bounded worker address limit")
    soft, hard = address_limits[0]

    status = (proc / "status").read_text(encoding="ascii")
    vm_sizes = re.findall(
        r"^VmSize:\s*([0-9]+)\s+kB\s*$",
        status,
        re.MULTILINE,
    )
    if len(vm_sizes) != 1:
        raise RuntimeError("could not parse one bounded worker VmSize")
    vm_size_kib = int(vm_sizes[0])
    if vm_size_kib <= 0 or vm_size_kib > ceiling // 1024:
        raise RuntimeError("bounded worker VmSize is outside the ceiling")
    vm_size_bytes = vm_size_kib * 1024
    if soft != hard or soft <= vm_size_bytes or soft > ceiling:
        raise RuntimeError("bounded worker address-space limit is unsafe")
    reserve = soft - vm_size_bytes
    if reserve < minimum_reserve:
        raise RuntimeError("bounded worker address-space reserve is too small")

    environment = (proc / "environ").read_bytes()
    if contains_secret(command_before) or contains_secret(environment):
        raise RuntimeError("raw bearer is present in a bounded worker")
    if os.stat(proc / "mem").st_uid != 0:
        raise RuntimeError("bounded worker memory remains dumpable")

    descriptor_directory = proc / "fd"
    descriptor_names = os.listdir(descriptor_directory)
    if any(not name.isdigit() for name in descriptor_names):
        raise RuntimeError("bounded worker exposed a nonnumeric descriptor")
    for descriptor_name in descriptor_names:
        descriptor = int(descriptor_name)
        descriptor_path = descriptor_directory / descriptor_name
        if os.readlink(descriptor_path) == listener_target:
            raise RuntimeError("bounded worker inherited the AF_INET listener")
        if descriptor <= 2:
            continue
        descriptor_info = (
            proc / "fdinfo" / descriptor_name
        ).read_text(encoding="ascii")
        flags = re.findall(
            r"^flags:\s*([0-7]+)\s*$",
            descriptor_info,
            re.MULTILINE,
        )
        if len(flags) != 1 or (int(flags[0], 8) & os.O_CLOEXEC) == 0:
            raise RuntimeError("bounded worker descriptor is not close-on-exec")

    start_after, parent_after, command_after = identity(proc)
    if (
        start_after != start_before
        or parent_after != parent_before
        or command_after != command_before
    ):
        raise RuntimeError("bounded worker identity changed during inspection")

    print(
        "storage worker address-space evidence: "
        f"build=systemd-test pid={pid} vm-size-kib={vm_size_kib} "
        f"soft-bytes={soft} hard-bytes={hard} reserve-bytes={reserve}"
    )
BOUNDED_PYTHON
  then
    fail "bounded storage worker runtime evidence failed"
  fi
}

print_capacity_journal_diagnostics() {
  local diagnostics

  if [[ -z "$capacity_journal_cursor" ||
    "$capacity_journal_cursor" == *$'\n'* ||
    "${#capacity_journal_cursor}" -gt 4096 ]]; then
    printf 'capacity journal diagnostics: cursor unavailable\n' >&2
    return
  fi
  if ! diagnostics="$(
    sudo journalctl \
      --unit="$service_unit" \
      --no-pager \
      --after-cursor="$capacity_journal_cursor" \
      --lines=2048 \
      --output=cat 2>/dev/null |
      awk '
        BEGIN {
          allowed["recasaos-systemd-test-event=handler-entered"] = 1
          allowed["recasaos-systemd-test-event=handler-download-slot-acquired"] = 1
          allowed["recasaos-systemd-test-event=handler-download-slot-rejected"] = 1
          allowed["recasaos-systemd-test-event=coordinator-context-rejected"] = 1
          allowed["recasaos-systemd-test-event=coordinator-pre-slot-rejected"] = 1
          allowed["recasaos-systemd-test-event=coordinator-manager-unavailable"] = 1
          allowed["recasaos-systemd-test-event=coordinator-signal-failure"] = 1
          allowed["recasaos-systemd-test-event=coordinator-quarantine-limit"] = 1
          allowed["recasaos-systemd-test-event=coordinator-slots-full"] = 1
          allowed["recasaos-systemd-test-event=coordinator-slot-acquired"] = 1
          allowed["recasaos-systemd-test-event=worker-start-capacity-failure"] = 1
          allowed["recasaos-systemd-test-event=worker-start-protocol-failure"] = 1
          allowed["recasaos-systemd-test-event=worker-post-start-rejected"] = 1
          allowed["recasaos-systemd-test-event=worker-process-registered"] = 1
          allowed["recasaos-systemd-test-event=coordinator-open-response"] = 1
          allowed["recasaos-systemd-test-event=coordinator-first-read-response"] = 1
          allowed["recasaos-systemd-test-event=child-first-read-sent"] = 1
        }
        {
          if ($0 in allowed) {
            print "capacity journal event: " $0
            event_count++
          } else if ($0 ~ /^recasaos-systemd-test-event=[a-z0-9-]+$/) {
            unknown_event = 1
          }

          known_fatal = 0
          if (index($0, "runtime: failed to create new OS thread") ||
            index($0, "fatal error: newosproc")) {
            new_thread = 1
            if (index($0, "errno=11)")) {
              new_thread_eagain = 1
            }
            if (index($0, "errno=12)")) {
              new_thread_enomem = 1
            }
            known_fatal = 1
          }
          if (index($0, "runtime: may need to increase max user processes")) {
            new_thread = 1
            new_thread_eagain = 1
            known_fatal = 1
          }
          if (index($0, "runtime: failed to allocate stack for the new OS thread")) {
            thread_stack_allocation = 1
            known_fatal = 1
          }
          if (index($0, "out of memory (stackalloc)")) {
            thread_stack_allocation = 1
            known_fatal = 1
          }
          if (index($0, "failed to reserve page summary memory")) {
            page_summary_reservation = 1
            known_fatal = 1
          }
          if (index($0, "out of memory") ||
            index($0, "cannot allocate memory")) {
            out_of_memory = 1
            known_fatal = 1
          }
          if (index($0, "cannot map pages in arena address space")) {
            arena_map_failure = 1
            known_fatal = 1
          }
          if (index($0, "memory reservation exceeds address space limit")) {
            arena_address_range = 1
            known_fatal = 1
          }
          if (index($0, "unexpected fault address") ||
            $0 == "fatal error: fault" ||
            index($0, "fatal error: unexpected signal during runtime execution")) {
            unexpected_fault = 1
            known_fatal = 1
          }
          if (index($0, "fatal error:") && !known_fatal) {
            other_fatal = 1
          }
        }
        END {
          printf "capacity journal summary: events=%d unknown-event=%s new-thread=%s new-thread-eagain=%s new-thread-enomem=%s thread-stack-allocation=%s page-summary-reservation=%s out-of-memory=%s arena-map-failure=%s arena-address-range=%s unexpected-fault=%s other-runtime-fatal=%s\n",
            event_count + 0,
            unknown_event ? "yes" : "no",
            new_thread ? "yes" : "no",
            new_thread_eagain ? "yes" : "no",
            new_thread_enomem ? "yes" : "no",
            thread_stack_allocation ? "yes" : "no",
            page_summary_reservation ? "yes" : "no",
            out_of_memory ? "yes" : "no",
            arena_map_failure ? "yes" : "no",
            arena_address_range ? "yes" : "no",
            unexpected_fault ? "yes" : "no",
            other_fatal ? "yes" : "no"
        }
      '
  )"; then
    printf 'capacity journal diagnostics: query failed\n' >&2
    return
  fi
  printf '%s\n' "$diagnostics" >&2
}

print_storage_worker_diagnostics() {
  local actual_worker_count
  local cgroup_file
  local client_index
  local client_pid
  local control_group
  local failure_file
  local failure_line
  local ready_file
  local start_time
  local worker_command
  local worker_end_command
  local worker_end_parent
  local worker_end_start_time
  local worker_limit_diagnostics
  local worker_parent
  local worker_pid
  local worker_pids
  local worker_resource_diagnostics
  local worker_start_time
  if worker_pids="$(storage_worker_pids 2>/dev/null)"; then
    if [[ -z "$worker_pids" ]]; then
      actual_worker_count=0
    elif ! actual_worker_count="$(
      printf '%s\n' "$worker_pids" |
        awk '
          NF != 1 || $1 !~ /^[0-9]+$/ || $1 <= 1 { exit 1 }
          { count++ }
          END { print count + 0 }
        '
    )"; then
      actual_worker_count=unknown
      worker_pids=unknown
    fi
  else
    actual_worker_count=unknown
    worker_pids=unknown
  fi
  printf 'storage worker diagnostics: actual=%s cached-last=%s cached-max=%s pids=%q\n' \
    "$actual_worker_count" \
    "$last_storage_worker_count" \
    "$max_storage_worker_count" \
    "$worker_pids" >&2
  sudo ps -o pid=,ppid=,stat=,etime=,args= --ppid "$portal_pid" >&2 || true
  while IFS= read -r worker_pid; do
    [[ "$worker_pid" =~ ^[0-9]+$ && "$worker_pid" -gt 1 ]] || continue
    sudo ps -L -o pid=,lwp=,ppid=,stat=,wchan=,comm= \
      -p "$worker_pid" >&2 || true
    worker_start_time="$(
      process_start_time "$worker_pid" 2>/dev/null || true
    )"
    worker_parent="$(
      sudo ps -o ppid= -p "$worker_pid" 2>/dev/null |
        awk 'NR == 1 { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print }' ||
        true
    )"
    worker_command="$(
      sudo cat "/proc/${worker_pid}/cmdline" 2>/dev/null |
        tr '\0' ' ' || true
    )"
    if [[ ! "$worker_start_time" =~ ^[0-9]+$ ||
      "$worker_parent" != "$portal_pid" ||
      "$worker_command" != '/proc/self/exe --internal-public-files-storage-worker file ' ]]; then
      printf 'storage worker resource diagnostics: identity unavailable\n' >&2
      continue
    fi
    if ! worker_resource_diagnostics="$(
      sudo awk '
        $1 == "VmSize:" { vm_size = $2 }
        $1 == "VmPeak:" { vm_peak = $2 }
        $1 == "VmRSS:" { vm_rss = $2 }
        $1 == "Threads:" { threads = $2 }
        END {
          if (vm_size == "") vm_size = "unknown"
          if (vm_peak == "") vm_peak = "unknown"
          if (vm_rss == "") vm_rss = "unknown"
          if (threads == "") threads = "unknown"
          printf "vm-size-kib=%s vm-peak-kib=%s vm-rss-kib=%s threads=%s\n",
            vm_size, vm_peak, vm_rss, threads
        }
      ' "/proc/${worker_pid}/status" 2>/dev/null
    )"; then
      printf 'storage worker resource diagnostics: identity unavailable\n' >&2
      continue
    fi
    if ! worker_limit_diagnostics="$(
      sudo awk '
        $1 == "Max" && $2 == "processes" {
          nproc_soft = $3
          nproc_hard = $4
        }
        $1 == "Max" && $2 == "address" && $3 == "space" {
          address_soft = $4
          address_hard = $5
        }
        END {
          if (nproc_soft == "") nproc_soft = "unknown"
          if (nproc_hard == "") nproc_hard = "unknown"
          if (address_soft == "") address_soft = "unknown"
          if (address_hard == "") address_hard = "unknown"
          printf "nproc-soft=%s nproc-hard=%s address-soft=%s address-hard=%s\n",
            nproc_soft, nproc_hard, address_soft, address_hard
        }
      ' "/proc/${worker_pid}/limits" 2>/dev/null
    )"; then
      printf 'storage worker resource diagnostics: identity unavailable\n' >&2
      continue
    fi
    worker_end_start_time="$(
      process_start_time "$worker_pid" 2>/dev/null || true
    )"
    worker_end_parent="$(
      sudo ps -o ppid= -p "$worker_pid" 2>/dev/null |
        awk 'NR == 1 { gsub(/^[[:space:]]+|[[:space:]]+$/, ""); print }' ||
        true
    )"
    worker_end_command="$(
      sudo cat "/proc/${worker_pid}/cmdline" 2>/dev/null |
        tr '\0' ' ' || true
    )"
    if [[ ! "$worker_end_start_time" =~ ^[0-9]+$ ||
      "$worker_end_start_time" != "$worker_start_time" ||
      "$worker_end_parent" != "$portal_pid" ||
      "$worker_end_parent" != "$worker_parent" ||
      "$worker_end_command" != "$worker_command" ||
      "$worker_end_command" != '/proc/self/exe --internal-public-files-storage-worker file ' ||
      ! "$worker_resource_diagnostics" =~ ^vm-size-kib=([0-9]+|unknown)\ vm-peak-kib=([0-9]+|unknown)\ vm-rss-kib=([0-9]+|unknown)\ threads=([0-9]+|unknown)$ ||
      ! "$worker_limit_diagnostics" =~ ^nproc-soft=([0-9]+|unlimited|unknown)\ nproc-hard=([0-9]+|unlimited|unknown)\ address-soft=([0-9]+|unlimited|unknown)\ address-hard=([0-9]+|unlimited|unknown)$ ]]; then
      printf 'storage worker resource diagnostics: identity unavailable\n' >&2
      continue
    fi
    printf 'storage worker resource diagnostics: pid=%s %s\n' \
      "$worker_pid" "$worker_resource_diagnostics" >&2
    printf 'storage worker limit diagnostics: pid=%s %s\n' \
      "$worker_pid" "$worker_limit_diagnostics" >&2
  done <<<"$worker_pids"
  for client_index in "${!slow_download_pids[@]}"; do
    client_pid="${slow_download_pids[$client_index]}"
    ready_file="${slow_download_ready_files[$client_index]}"
    failure_file="${slow_download_failure_files[$client_index]}"
    start_time="${slow_download_start_times[$client_index]}"
    if slow_download_process_is_live "$client_pid" "$start_time"; then
      printf 'slow download client %s: alive ready=%s failure=%s\n' \
        "$client_pid" \
        "$(slow_download_marker_is_valid "$ready_file" &&
          printf yes || printf no)" \
        "$([[ -s "$failure_file" ]] && printf yes || printf no)" >&2
    else
      printf 'slow download client %s: exited ready=%s failure=%s\n' \
        "$client_pid" \
        "$(slow_download_marker_is_valid "$ready_file" &&
          printf yes || printf no)" \
        "$([[ -s "$failure_file" ]] && printf yes || printf no)" >&2
    fi
    if [[ -s "$failure_file" ]]; then
      while IFS= read -r failure_line; do
        printf 'slow download client %s error: %s\n' \
          "$client_pid" "$failure_line" >&2
      done <"$failure_file"
    fi
  done
  sudo systemctl show \
    --property=ActiveState \
    --property=SubState \
    --property=MainPID \
    --property=InvocationID \
    --property=NRestarts \
    --property=Result \
    --property=ExecMainCode \
    --property=ExecMainStatus \
    --property=ControlGroup \
    --property=TasksCurrent \
    --property=TasksMax \
    --property=MemoryCurrent \
    --property=MemoryMax \
    "$service_unit" >&2 || true
  sudo systemctl show \
    --property=MemoryPeak \
    "$service_unit" >&2 2>/dev/null || true
  control_group="$(
    sudo systemctl show --property=ControlGroup --value \
      "$service_unit" 2>/dev/null || true
  )"
  if [[ "$control_group" == "/system.slice/$service_unit" ]]; then
    for cgroup_file in \
      memory.current \
      memory.peak \
      memory.max \
      memory.events \
      pids.current \
      pids.max \
      pids.events
    do
      if sudo test -f \
        "/sys/fs/cgroup${control_group}/${cgroup_file}"; then
        printf 'service cgroup %s:\n' "$cgroup_file" >&2
        sudo cat \
          "/sys/fs/cgroup${control_group}/${cgroup_file}" >&2 || true
      fi
    done
  fi
  sudo ss -H -tinp \
    '( sport = :39777 or dport = :39777 )' >&2 || true
  print_capacity_journal_diagnostics
  sudo journalctl --no-pager --output=short-monotonic --lines=80 \
    --unit="$socket_unit" --unit="$service_unit" >&2 || true
}

capture_capacity_journal_cursor() {
  local cursor

  [[ "$capacity_events" == "$workspace/capacity-events" ]] ||
    fail "refusing unsafe capacity event path: $capacity_events"
  [[ ! -e "$capacity_events" && ! -L "$capacity_events" ]] ||
    fail "capacity event path already exists"
  install -m 0600 /dev/null "$capacity_events"
  cursor="$(
    sudo journalctl \
      --unit="$service_unit" \
      --no-pager \
      --lines=1 \
      --show-cursor \
      --output=cat |
      awk '
        /^-- cursor: / {
          count++
          sub(/^-- cursor: /, "")
          cursor = $0
        }
        END {
          if (count != 1 || cursor == "")
            exit 1
          print cursor
        }
      '
  )" || fail "could not capture the capacity-phase journal cursor"
  [[ -n "$cursor" && "$cursor" != *$'\n'* &&
    "${#cursor}" -le 4096 ]] ||
    fail "capacity-phase journal cursor is unsafe"
  capacity_journal_cursor=$cursor
}

capacity_phase_events_are_complete() {
  [[ -n "$capacity_journal_cursor" &&
    "$capacity_journal_cursor" != *$'\n'* &&
    "${#capacity_journal_cursor}" -le 4096 ]] || return 1
  [[ -f "$capacity_events" && ! -L "$capacity_events" ]] || return 1
  sudo journalctl \
    --unit="$service_unit" \
    --no-pager \
    --after-cursor="$capacity_journal_cursor" \
    --output=cat |
    awk '
      /^recasaos-systemd-test-event=[a-z0-9-]+$/ &&
        length($0) <= 96 {
        print
      }
    ' >"$capacity_events" || return 1
  awk '
    BEGIN {
      # Eight successful holders emit seven events each. The coordinator
      # records only the first successful read for each holder: under slow
      # emulation the child can complete already queued reads before its
      # process-wide SIGSTOP is observed, and those extra reads are not new
      # worker admissions. The ninth request
      # enters the handler, acquires one of 64 download slots, then reaches the
      # independently bounded eight-worker coordinator and is rejected there.
      expected["recasaos-systemd-test-event=handler-entered"] = 9
      expected["recasaos-systemd-test-event=handler-download-slot-acquired"] = 9
      expected["recasaos-systemd-test-event=handler-download-slot-rejected"] = 0
      expected["recasaos-systemd-test-event=coordinator-context-rejected"] = 0
      expected["recasaos-systemd-test-event=coordinator-pre-slot-rejected"] = 0
      expected["recasaos-systemd-test-event=coordinator-manager-unavailable"] = 0
      expected["recasaos-systemd-test-event=coordinator-signal-failure"] = 0
      expected["recasaos-systemd-test-event=coordinator-quarantine-limit"] = 0
      expected["recasaos-systemd-test-event=coordinator-slots-full"] = 1
      expected["recasaos-systemd-test-event=coordinator-slot-acquired"] = 8
      expected["recasaos-systemd-test-event=worker-start-capacity-failure"] = 0
      expected["recasaos-systemd-test-event=worker-start-protocol-failure"] = 0
      expected["recasaos-systemd-test-event=worker-post-start-rejected"] = 0
      expected["recasaos-systemd-test-event=worker-process-registered"] = 8
      expected["recasaos-systemd-test-event=coordinator-open-response"] = 8
      expected["recasaos-systemd-test-event=coordinator-first-read-response"] = 8
      expected["recasaos-systemd-test-event=child-first-read-sent"] = 8
    }
    { observed[$0]++ }
    END {
      for (event in observed)
        if (!(event in expected))
          exit 1
      for (event in expected)
        if (observed[event] + 0 != expected[event])
          exit 1
    }
  ' "$capacity_events"
}

slow_download_marker_is_valid() {
  local marker_value
  local ready_file=$1

  [[ -f "$ready_file" && ! -L "$ready_file" ]] || return 1
  marker_value="$(<"$ready_file")"
  [[ "$marker_value" == ready ]]
}

slow_download_is_ready() {
  local failure_file=$3
  local pid=$1
  local ready_file=$2
  local start_time=$4

  if [[ -s "$failure_file" ]]; then
    print_storage_worker_diagnostics
    fail "slow download client $pid failed before becoming ready"
  fi
  if [[ -e "$ready_file" || -L "$ready_file" ]]; then
    [[ -f "$ready_file" && ! -L "$ready_file" ]] ||
      fail "slow download client $pid produced an unsafe ready marker"
    slow_download_marker_is_valid "$ready_file" ||
      fail "slow download client $pid produced an invalid ready marker"
    slow_download_process_is_live "$pid" "$start_time" ||
      fail "slow download client $pid exited after becoming ready"
    return 0
  fi
  slow_download_process_is_live "$pid" "$start_time" ||
    fail "slow download client $pid exited before becoming ready"
  return 1
}

slow_downloads_are_healthy() {
  local client_index

  for client_index in "${!slow_download_pids[@]}"; do
    slow_download_is_ready \
      "${slow_download_pids[$client_index]}" \
      "${slow_download_ready_files[$client_index]}" \
      "${slow_download_failure_files[$client_index]}" \
      "${slow_download_start_times[$client_index]}" || return 1
  done
}

start_slow_download() {
  local failure_file
  local pid
  local ready_file
  local ready_temp_file
  local start_time

  slow_download_sequence=$((slow_download_sequence + 1))
  ready_file="${workspace}/slow-download-${slow_download_sequence}.ready"
  ready_temp_file="${ready_file}.tmp"
  failure_file="${workspace}/slow-download-${slow_download_sequence}.failure"
  [[ "$ready_file" == "$workspace/slow-download-${slow_download_sequence}.ready" ]] ||
    fail "refusing unsafe slow download ready path: $ready_file"
  [[ "$failure_file" == "$workspace/slow-download-${slow_download_sequence}.failure" ]] ||
    fail "refusing unsafe slow download failure path: $failure_file"
  [[ ! -e "$ready_file" && ! -L "$ready_file" &&
    ! -e "$ready_temp_file" && ! -L "$ready_temp_file" &&
    ! -e "$failure_file" && ! -L "$failure_file" ]] ||
    fail "slow download state path already exists"
  install -m 0600 /dev/null "$failure_file"

  printf '%s\n' "$test_bearer" |
    /usr/bin/python3 -c '
import os
import re
import socket
import sys
import time

try:
    token_input = sys.stdin.buffer.read(129)
    if len(token_input) > 128 or not token_input.endswith(b"\n"):
        raise ValueError("invalid bounded bearer input")
    token = token_input[:-1]
    if re.fullmatch(rb"rc1_[A-Za-z0-9_-]{43}", token) is None:
        raise ValueError("invalid bearer format")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(("127.0.0.1", 39777))
    client.sendall(
        b"GET /public-files/api/file?path=worker-load.bin HTTP/1.1\r\n"
        b"Host: 127.0.0.1:39777\r\n"
        b"Authorization: Bearer " + token + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = client.recv(4096)
        if not chunk:
            raise RuntimeError(
                "server closed before response headers; "
                f"bytes_before_eof={len(response)}"
            )
        response.extend(chunk)
        if len(response) > 32768:
            raise RuntimeError("response headers exceeded the bounded limit")
    header_block, initial_body = bytes(response).split(b"\r\n\r\n", 1)
    header_lines = header_block.split(b"\r\n")
    status_match = re.fullmatch(
        rb"HTTP/1\.1 ([1-5][0-9]{2}) [\x20-\x7e]{1,64}",
        header_lines[0],
    )
    if status_match is None:
        raise RuntimeError("slow download received an invalid status line")
    status_code = int(status_match.group(1))
    content_lengths = []
    retry_after_values = []
    transfer_encodings = []
    for header_line in header_lines[1:]:
        if b":" not in header_line:
            raise RuntimeError("slow download received a malformed header")
        header_name, header_value = header_line.split(b":", 1)
        if not header_name or header_name != header_name.strip():
            raise RuntimeError("slow download received a malformed header name")
        header_name = header_name.lower()
        if header_name == b"content-length":
            content_lengths.append(header_value.strip())
        elif header_name == b"retry-after":
            retry_after_values.append(header_value.strip())
        elif header_name == b"transfer-encoding":
            transfer_encodings.append(header_value.strip())
    if header_lines[0] != b"HTTP/1.1 200 OK":
        error_class = "unclassified"
        if (
            len(content_lengths) == 1
            and re.fullmatch(rb"[0-9]{1,3}", content_lengths[0])
            and not transfer_encodings
        ):
            body_length = int(content_lengths[0])
            if body_length <= 512 and len(initial_body) <= body_length:
                body = bytearray(initial_body)
                while len(body) < body_length:
                    chunk = client.recv(body_length - len(body))
                    if not chunk:
                        break
                    body.extend(chunk)
                if len(body) != body_length:
                    error_class = "truncated-bounded-error"
                else:
                    error_class = {
                        b"{\"error\":\"storage capacity unavailable\"}":
                            "storage-capacity-unavailable",
                        b"{\"error\":\"download capacity reached\"}":
                            "download-capacity-reached",
                        b"{\"error\":\"unable to open file\"}":
                            "unable-to-open-file",
                    }.get(bytes(body), "unrecognized-bounded-error")
        retry_after_5 = (
            "yes" if retry_after_values == [b"5"] else "no"
        )
        raise RuntimeError(
            "slow download rejected: "
            f"status={status_code} "
            f"retry_after_5={retry_after_5} "
            f"error={error_class}"
        )
    expected_length = sys.argv[2].encode("ascii")
    if expected_length != b"67108864":
        raise RuntimeError("slow download fixture length is invalid")
    if content_lengths != [expected_length] or transfer_encodings:
        raise RuntimeError("slow download received unsafe framing headers")

    marker_path = sys.argv[1]
    marker_temp_path = marker_path + ".tmp"
    marker = b"ready\n"
    marker_fd = os.open(
        marker_temp_path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
        0o600,
    )
    try:
        if os.write(marker_fd, marker) != len(marker):
            raise RuntimeError("could not write the complete ready marker")
    finally:
        os.close(marker_fd)
    os.link(marker_temp_path, marker_path, follow_symlinks=False)
    os.unlink(marker_temp_path)

    client.settimeout(None)
    if not hasattr(socket, "TCP_INFO"):
        raise RuntimeError("kernel TCP connection state is unavailable")
    for _ in range(1200):
        tcp_state = client.getsockopt(
            socket.IPPROTO_TCP,
            socket.TCP_INFO,
            1,
        )[0]
        if tcp_state != 1:
            raise RuntimeError(
                "slow download connection closed before holder release"
            )
        time.sleep(0.1)
except Exception as error:
    print(
        "slow download holder failed: "
        f"{type(error).__name__}: {error}",
        file=sys.stderr,
        flush=True,
    )
    raise SystemExit(1)
' "$ready_file" "$worker_load_bytes" 2>"$failure_file" &
  pid=$!
  start_time="$(process_start_time "$pid")" || {
    wait "$pid" 2>/dev/null || true
    fail "slow download client exited before identity capture"
  }
  slow_download_pids+=("$pid")
  slow_download_ready_files+=("$ready_file")
  slow_download_failure_files+=("$failure_file")
  slow_download_start_times+=("$start_time")
  latest_slow_download_pid=$pid
  latest_slow_download_ready_file=$ready_file
  latest_slow_download_failure_file=$failure_file
  latest_slow_download_start_time=$start_time
}

process_identity_is_gone() {
  local current_start_time
  local expected_start_time=$2
  local pid=$1

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 &&
    "$expected_start_time" =~ ^[0-9]+$ ]] || return 1
  [[ ! -e "/proc/$pid" ]] && return 0
  current_start_time="$(process_start_time "$pid")" || return 1
  [[ "$current_start_time" != "$expected_start_time" ]]
}

sentinel_is_unchanged() {
  current_pid="$(sudo systemctl show --property=MainPID --value "$sentinel_unit")"
  current_invocation="$(
    sudo systemctl show --property=InvocationID --value "$sentinel_unit"
  )"
  [[ "$current_pid" == "$sentinel_pid" &&
    "$current_invocation" == "$sentinel_invocation" ]] || return 1
  [[ "$(
    curl -q -sS --max-time 1 -o /dev/null -w '%{http_code}' \
      http://127.0.0.1:39888/health.txt 2>/dev/null || true
  )" == 200 ]]
}

sentinel_is_active() {
  sudo systemctl is-active --quiet "$sentinel_unit"
}

service_is_deactivating() {
  [[ "$(
    sudo systemctl show --property=ActiveState --value "$service_unit"
  )" == deactivating ]]
}

setup_hostile_storage_fuse_backing() {
  local connection
  local daemon_deadline
  local device_metadata
  local fuse_control_type
  local mount_count
  local mount_evidence
  local -a fuse_connections=()

  [[ "$hostile_storage_test_enabled" == 1 ]] || return 0
  [[ -d "$hostile_storage_fuse_source" &&
    ! -L "$hostile_storage_fuse_source" &&
    -d "$hostile_storage_fuse_mount" &&
    ! -L "$hostile_storage_fuse_mount" ]] ||
    fail "hostile-storage FUSE directories are unsafe"
  [[ -z "$(find "$hostile_storage_fuse_source" -mindepth 1 -print -quit)" &&
    -z "$(find "$hostile_storage_fuse_mount" -mindepth 1 -print -quit)" ]] ||
    fail "hostile-storage FUSE directories are not empty"
  [[ ! -e "$hostile_storage_fuse_log" &&
    ! -L "$hostile_storage_fuse_log" ]] ||
    fail "hostile-storage FUSE log path already exists"

  sudo modprobe fuse
  sudo udevadm settle --timeout=10 ||
    fail "udev did not settle after FUSE module loading"
  sudo test -c /dev/fuse || fail "isolated VM FUSE device is unavailable"
  device_metadata="$(stat -c '%t:%T:%u:%g:%a' /dev/fuse)" ||
    fail "could not inspect the isolated VM FUSE device"
  [[ "$device_metadata" == a:e5:0:0:666 ]] ||
    fail "isolated VM FUSE device metadata is unsafe: $device_metadata"

  fuse_control_type="$(stat -fc %T /sys/fs/fuse/connections)" ||
    fail "could not inspect the FUSE control path"
  if [[ "$fuse_control_type" != fusectl ]]; then
    mount_count="$(
      awk '$5 == "/sys/fs/fuse/connections" { count++ }
        END { print count + 0 }' /proc/self/mountinfo
    )" || fail "could not inspect the FUSE control mount"
    [[ "$mount_count" == 0 ]] ||
      fail "an unexpected filesystem covers the FUSE control path"
    sudo mount -t fusectl -o nodev,nosuid,noexec \
      fusectl /sys/fs/fuse/connections
    hostile_storage_fuse_control_mounted=1
  fi
  [[ "$(stat -fc %T /sys/fs/fuse/connections)" == fusectl ]] ||
    fail "FUSE control filesystem is unavailable"
  mapfile -t fuse_connections < <(
    find /sys/fs/fuse/connections -mindepth 1 -maxdepth 1 \
      -type d -printf '%f\n' | LC_ALL=C sort
  )
  [[ "${#fuse_connections[@]}" == 0 ]] ||
    fail "isolated VM already has a FUSE connection"

  truncate -s 268435456 "$hostile_storage_backing_source"
  chmod 0600 "$hostile_storage_backing_source"
  install -m 0600 /dev/null "$hostile_storage_fuse_log"
  hostile_storage_fuse_daemon_executable="$(
    readlink -f "$(command -v bindfs)"
  )" || fail "could not resolve the hostile-storage FUSE daemon"
  [[ "$hostile_storage_fuse_daemon_executable" == /usr/bin/bindfs ]] ||
    fail "unexpected hostile-storage FUSE daemon: $hostile_storage_fuse_daemon_executable"
  hostile_storage_fusermount_executable="$(
    readlink -f "$(command -v fusermount)"
  )" || fail "could not resolve the hostile-storage FUSE unmount helper"
  [[ "$hostile_storage_fusermount_executable" == /usr/bin/fusermount ]] ||
    fail \
      "unexpected hostile-storage FUSE unmount helper: $hostile_storage_fusermount_executable"
  "$hostile_storage_fuse_daemon_executable" \
    -f \
    --no-allow-other \
    -o "$hostile_storage_fuse_options" \
    "$hostile_storage_fuse_source" \
    "$hostile_storage_fuse_mount" \
    >"$hostile_storage_fuse_log" 2>&1 &
  hostile_storage_fuse_daemon_pid=$!
  hostile_storage_fuse_daemon_start_time="$(
    process_start_time "$hostile_storage_fuse_daemon_pid"
  )" || {
    wait "$hostile_storage_fuse_daemon_pid" 2>/dev/null || true
    sed -n '1,20p' "$hostile_storage_fuse_log" >&2
    fail "could not record the hostile-storage FUSE daemon identity"
  }
  hostile_storage_fuse_daemon_started=1
  daemon_deadline=$((SECONDS + 5))
  while ! hostile_storage_fuse_daemon_is_exact &&
    ((SECONDS < daemon_deadline)); do
    if hostile_storage_fuse_daemon_process_is_gone; then
      sed -n '1,20p' "$hostile_storage_fuse_log" >&2
      fail "hostile-storage FUSE daemon exited before exact identity capture"
    fi
    sleep 0.02
  done
  hostile_storage_fuse_daemon_is_exact ||
    fail "hostile-storage FUSE daemon identity is unsafe"

  while [[ "$(
    awk -v target="$hostile_storage_fuse_mount" \
      '$5 == target { count++ } END { print count + 0 }' \
      /proc/self/mountinfo
  )" != 1 ]] && ((SECONDS < daemon_deadline)); do
    hostile_storage_fuse_daemon_is_exact ||
      fail "hostile-storage FUSE daemon changed before mount readiness"
    sleep 0.02
  done
  mount_evidence="$(
    awk -v target="$hostile_storage_fuse_mount" \
      -v expected_uid="$runner_uid" -v expected_gid="$runner_gid" '
      function has_option(options, wanted, count, values, option_index) {
        count = split(options, values, ",")
        for (option_index = 1; option_index <= count; option_index++)
          if (values[option_index] == wanted)
            return 1
        return 0
      }
      {
        separator = 0
        for (field_index = 7; field_index <= NF; field_index++)
          if ($field_index == "-") {
            separator = field_index
            break
          }
        if ($5 != target)
          next
        matches++
        if (!has_option($6, "rw") ||
            !has_option($6, "nodev") ||
            !has_option($6, "nosuid") ||
            !has_option($6, "noexec") ||
            separator == 0 ||
            $(separator + 1) != "fuse.bindfs" ||
            !has_option($(separator + 3), "user_id=" expected_uid) ||
            !has_option($(separator + 3), "group_id=" expected_gid))
          invalid++
      }
      END { printf "%d:%d\n", matches + 0, invalid + 0 }
    ' /proc/self/mountinfo
  )" || fail "could not inspect hostile-storage FUSE mount"
  [[ "$mount_evidence" == 1:0 ]] ||
    fail "hostile-storage FUSE mount evidence is unsafe: $mount_evidence"
  hostile_storage_fuse_mounted=1

  mapfile -t fuse_connections < <(
    find /sys/fs/fuse/connections -mindepth 1 -maxdepth 1 \
      -type d -printf '%f\n' | LC_ALL=C sort
  )
  [[ "${#fuse_connections[@]}" == 1 ]] ||
    fail "hostile-storage FUSE connection count is unsafe"
  connection="${fuse_connections[0]}"
  [[ "$connection" =~ ^[0-9]+$ ]] ||
    fail "hostile-storage FUSE connection identity is unsafe: $connection"
  hostile_storage_fuse_connection=$connection
  [[ "$(hostile_storage_fuse_waiting_value)" == 0 ]] ||
    fail "new hostile-storage FUSE connection already has waiting requests"
  hostile_storage_fuse_daemon_is_resumed ||
    fail "new hostile-storage FUSE daemon is not runnable"
  [[ -f "$hostile_storage_backing" && ! -L "$hostile_storage_backing" &&
    "$(stat -c %s "$hostile_storage_backing")" == 268435456 ]] ||
    fail "hostile-storage FUSE backing file is unsafe"
}

setup_hostile_storage_share() {
  local device_identity
  local nbd_connection_status
  local nbd_client_deadline
  local nbd_client_executable
  local nbd_client_expected_executable
  local mount_evidence
  local nbd_client_pid
  local nbd_client_start_time
  local nbd_client_uid
  local nbd_identity
  local nbd_listener_count
  local nbd_server_deadline
  local nbd_server_pid_metadata
  local nbd_server_pid_file_value
  local sectors
  local table

  [[ "$hostile_storage_test_enabled" == 1 ]] || return 0
  [[ -d "$share" && ! -L "$share" ]] ||
    fail "hostile-storage share target is unsafe"
  [[ -z "$(find "$share" -mindepth 1 -print -quit)" ]] ||
    fail "hostile-storage share target is not empty"
  [[ ! -e "$hostile_storage_backing_source" &&
    ! -L "$hostile_storage_backing_source" &&
    ! -e "$hostile_storage_backing" &&
    ! -L "$hostile_storage_backing" ]] ||
    fail "hostile-storage backing path already exists"
  if sudo dmsetup info "$hostile_storage_name" >/dev/null 2>&1; then
    fail "hostile-storage mapping already exists"
  fi
  [[ ! -e "$hostile_storage_nbd_pid_file" &&
    ! -L "$hostile_storage_nbd_pid_file" ]] ||
    fail "hostile-storage NBD PID path already exists"
  nbd_listener_count="$(
    sudo ss -H -ltn "sport = :$hostile_storage_nbd_port" |
      awk 'END { print NR + 0 }'
  )" || fail "could not inspect the hostile-storage NBD port"
  [[ "$nbd_listener_count" == 0 ]] ||
    fail "hostile-storage NBD port is already bound"

  setup_hostile_storage_fuse_backing
  sudo modprobe nbd nbds_max=1 max_part=0
  sudo modprobe dm_mod
  sudo udevadm settle --timeout=10 ||
    fail "udev did not settle after hostile-storage module loading"
  [[ "$(sudo cat /sys/module/nbd/parameters/nbds_max)" == 1 &&
    "$(sudo cat /sys/module/nbd/parameters/max_part)" == 0 ]] ||
    fail "isolated VM NBD module parameters are not exact"
  [[ "$(find /sys/block -maxdepth 1 -type l -name 'nbd*' -print)" == \
    /sys/block/nbd0 ]] ||
    fail "isolated VM does not expose exactly one NBD device"
  sudo test -b "$hostile_storage_nbd_device" ||
    fail "isolated VM NBD device is unavailable"
  if sudo nbd-client -c \
    "$hostile_storage_nbd_device" >/dev/null 2>&1; then
    nbd_connection_status=0
  else
    nbd_connection_status=$?
  fi
  case "$nbd_connection_status" in
    0) fail "isolated VM NBD device is already connected" ;;
    1) ;;
    *) fail \
      "could not prove the isolated VM NBD device is disconnected" ;;
  esac
  sudo test -c /dev/mapper/control ||
    fail "isolated VM device-mapper control node is unavailable"
  sudo dmsetup targets |
    awk '$1 == "linear" { found = 1 } END { exit found ? 0 : 1 }' ||
    fail "device-mapper linear target is unavailable"

  hostile_storage_nbd_server_executable="$(
    readlink -f "$(command -v qemu-nbd)"
  )" || fail "could not resolve the hostile-storage NBD server executable"
  [[ "$hostile_storage_nbd_server_executable" == /usr/bin/qemu-nbd ]] ||
    fail \
      "unexpected hostile-storage NBD server: $hostile_storage_nbd_server_executable"
  [[ ! -e "$hostile_storage_nbd_log" &&
    ! -L "$hostile_storage_nbd_log" ]] ||
    fail "hostile-storage NBD log path already exists"
  install -m 0600 /dev/null "$hostile_storage_nbd_log"
  "$hostile_storage_nbd_server_executable" \
    --persistent \
    --shared=1 \
    --bind=127.0.0.1 \
    --port="$hostile_storage_nbd_port" \
    --export-name="$hostile_storage_nbd_export" \
    --format=raw \
    --cache=none \
    --aio=threads \
    --pid-file="$hostile_storage_nbd_pid_file" \
    "$hostile_storage_backing" \
    >/dev/null 2>"$hostile_storage_nbd_log" &
  hostile_storage_nbd_server_pid=$!
  hostile_storage_nbd_server_start_time="$(
    process_start_time "$hostile_storage_nbd_server_pid"
  )" || {
    wait "$hostile_storage_nbd_server_pid" 2>/dev/null || true
    sed -n '1,20p' "$hostile_storage_nbd_log" >&2
    fail "could not record the hostile-storage NBD server identity"
  }
  hostile_storage_nbd_server_started=1
  nbd_server_deadline=$((SECONDS + 5))
  while ! hostile_storage_nbd_server_is_exact &&
    ((SECONDS < nbd_server_deadline)); do
    if hostile_storage_nbd_server_process_is_gone; then
      sed -n '1,20p' "$hostile_storage_nbd_log" >&2
      fail "hostile-storage NBD server exited before exact identity capture"
    fi
    sleep 0.02
  done
  hostile_storage_nbd_server_is_exact ||
    fail "hostile-storage NBD server identity is unsafe"
  while [[ ! -f "$hostile_storage_nbd_pid_file" ]] &&
    ((SECONDS < nbd_server_deadline)); do
    hostile_storage_nbd_server_is_exact || {
      sed -n '1,20p' "$hostile_storage_nbd_log" >&2
      fail "hostile-storage NBD server exited before creating its PID file"
    }
    sleep 0.02
  done
  [[ -f "$hostile_storage_nbd_pid_file" &&
    ! -L "$hostile_storage_nbd_pid_file" ]] ||
    fail "hostile-storage NBD server did not create a safe PID file"
  nbd_server_pid_metadata="$(
    stat -c '%u:%h' "$hostile_storage_nbd_pid_file"
  )" || fail "could not inspect the hostile-storage NBD PID file"
  [[ "$nbd_server_pid_metadata" == "$(id -u):1" ]] ||
    fail \
      "hostile-storage NBD PID file metadata is unsafe: $nbd_server_pid_metadata"
  nbd_server_pid_file_value="$(
    tr -d '[:space:]' <"$hostile_storage_nbd_pid_file"
  )" || fail "could not read the hostile-storage NBD server PID"
  [[ "$nbd_server_pid_file_value" =~ ^[0-9]+$ &&
    "$nbd_server_pid_file_value" -gt 1 &&
    "$nbd_server_pid_file_value" == \
      "$hostile_storage_nbd_server_pid" ]] ||
    fail "hostile-storage NBD server PID is invalid"
  hostile_storage_nbd_server_is_exact ||
    fail "hostile-storage NBD server identity is unsafe"
  while ! hostile_storage_nbd_listener_is_exact &&
    ((SECONDS < nbd_server_deadline)); do
    sleep 0.02
  done
  if ! hostile_storage_nbd_listener_is_exact; then
    sed -n '1,20p' "$hostile_storage_nbd_log" >&2
    fail "hostile-storage NBD server is not the exact loopback listener"
  fi

  # Debian 11 nbd-client defaults to netlink and exits after handing its
  # socket to the kernel. Force the long-lived ioctl client so the kernel PID
  # attribute is a stable, live client identity throughout the fault test.
  if ! timeout --signal=TERM --kill-after=5s 10s \
    sudo nbd-client \
      --nonetlink \
      127.0.0.1 \
      "$hostile_storage_nbd_port" \
      "$hostile_storage_nbd_device" \
      -N "$hostile_storage_nbd_export"; then
    if sudo nbd-client -c \
      "$hostile_storage_nbd_device" >/dev/null 2>&1; then
      hostile_storage_nbd_connected=1
    fi
    fail "could not connect the hostile-storage NBD device"
  fi
  hostile_storage_nbd_connected=1
  nbd_client_expected_executable="$(
    readlink -f "$(command -v nbd-client)"
  )" || fail "could not resolve the hostile-storage NBD client"
  [[ "$nbd_client_expected_executable" == /usr/sbin/nbd-client ]] ||
    fail "unexpected hostile-storage NBD client: $nbd_client_expected_executable"
  nbd_client_deadline=$((SECONDS + 5))
  nbd_client_pid=
  while ((SECONDS < nbd_client_deadline)); do
    if nbd_client_pid="$(
      sudo nbd-client -c "$hostile_storage_nbd_device" |
        tr -d '[:space:]'
    )" && [[ "$nbd_client_pid" =~ ^[0-9]+$ && "$nbd_client_pid" -gt 1 ]]; then
      break
    fi
    nbd_client_pid=
    hostile_storage_nbd_server_is_exact ||
      fail "hostile-storage NBD server changed before client readiness"
    hostile_storage_nbd_listener_is_exact ||
      fail "hostile-storage NBD listener changed before client readiness"
    sleep 0.02
  done
  [[ "$nbd_client_pid" =~ ^[0-9]+$ && "$nbd_client_pid" -gt 1 ]] ||
    fail "hostile-storage NBD client PID is invalid: $nbd_client_pid"
  nbd_client_start_time="$(process_start_time "$nbd_client_pid")" ||
    fail "could not capture the hostile-storage NBD client identity"
  nbd_client_executable="$(
    sudo readlink -f "/proc/$nbd_client_pid/exe"
  )" || fail "could not inspect the hostile-storage NBD client executable"
  nbd_client_uid="$(
    awk '$1 == "Uid:" { print $2 ":" $3 ":" $4 ":" $5; exit }' \
      "/proc/$nbd_client_pid/status"
  )" || fail "could not inspect the hostile-storage NBD client UID"
  [[ "$nbd_client_executable" == "$nbd_client_expected_executable" &&
    "$nbd_client_uid" == 0:0:0:0 ]] ||
    fail "hostile-storage NBD client process identity is unsafe"
  [[ "$(sudo cat /sys/block/nbd0/pid)" == "$nbd_client_pid" ]] ||
    fail "hostile-storage NBD kernel identity changed"
  [[ "$(process_start_time "$nbd_client_pid")" == \
    "$nbd_client_start_time" ]] ||
    fail "hostile-storage NBD client process identity changed"
  sectors="$(sudo blockdev --getsz "$hostile_storage_nbd_device")" ||
    fail "could not inspect hostile-storage NBD size"
  [[ "$sectors" =~ ^[0-9]+$ && "$sectors" -eq 524288 ]] ||
    fail "hostile-storage NBD device has unexpected sectors: $sectors"
  nbd_identity="$(
    lsblk --noheadings --nodeps --output MAJ:MIN \
      "$hostile_storage_nbd_device" |
      tr -d '[:space:]'
  )" || fail "could not inspect hostile-storage NBD identity"
  [[ "$nbd_identity" == 43:0 ]] ||
    fail "hostile-storage NBD identity is unexpected: $nbd_identity"

  table="0 $sectors linear $nbd_identity 0"
  if ! sudo dmsetup create "$hostile_storage_name" --table "$table"; then
    if sudo dmsetup info "$hostile_storage_name" >/dev/null 2>&1; then
      hostile_storage_dm_created=1
      record_hostile_storage_device_identity || true
    fi
    fail "could not create hostile-storage mapping"
  fi
  hostile_storage_dm_created=1
  record_hostile_storage_device_identity ||
    fail "could not inspect hostile-storage device identity"
  sudo udevadm settle --timeout=10 ||
    fail "udev did not settle after hostile-storage mapping creation"
  sudo test -b "$hostile_storage_mapper" ||
    fail "hostile-storage mapper node is unavailable"
  [[ "$(sudo dmsetup table "$hostile_storage_name")" == "$table" ]] ||
    fail "hostile-storage mapping table changed"

  device_identity="${hostile_storage_major}:${hostile_storage_minor}"
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "new hostile-storage mapping is unexpectedly suspended"

  sudo mkfs.ext4 -q -F -m 0 "$hostile_storage_mapper"
  if ! sudo mount -t ext4 -o nodev,nosuid,noexec \
    "$hostile_storage_mapper" "$share"; then
    if awk -v target="$share" '$5 == target { found = 1 }
      END { exit found ? 0 : 1 }' /proc/self/mountinfo; then
      hostile_storage_share_mounted=1
    fi
    fail "could not mount hostile-storage share"
  fi
  hostile_storage_share_mounted=1
  mount_evidence="$(
    awk -v target="$share" -v identity="$device_identity" '
      function has_option(options, wanted, count, values, option_index) {
        count = split(options, values, ",")
        for (option_index = 1; option_index <= count; option_index++)
          if (values[option_index] == wanted)
            return 1
        return 0
      }
      {
        separator = 0
        for (field_index = 7; field_index <= NF; field_index++)
          if ($field_index == "-") {
            separator = field_index
            break
          }
        if ($5 != target)
          next
        matches++
        if ($3 != identity ||
            !has_option($6, "rw") ||
            !has_option($6, "nodev") ||
            !has_option($6, "nosuid") ||
            !has_option($6, "noexec") ||
            separator == 0 ||
            $(separator + 1) != "ext4")
          invalid++
      }
      END { printf "%d:%d\n", matches + 0, invalid + 0 }
    ' /proc/self/mountinfo
  )" || fail "could not inspect hostile-storage share mount"
  [[ "$mount_evidence" == 1:0 ]] ||
    fail "hostile-storage share mount evidence is unsafe: $mount_evidence"
}

runner_uid="$(id -u)"
runner_gid="$(id -g)"
sudo install -d -o "$runner_uid" -g "$runner_gid" -m 0755 \
  "$workspace" \
  "$hostile_storage_fuse_source" \
  "$hostile_storage_fuse_mount"
sudo install -d -o root -g root -m 0755 \
  "$rootfs" "$rootfs/usr" "$rootfs/usr/bin" "$rootfs/srv" \
  "$rootfs/proc" "$rootfs/sys" "$rootfs/dev" "$rootfs/run" \
  "$rootfs/tmp" "$rootfs/var" "$rootfs/var/tmp"
sudo install -d -o root -g root -m 0555 \
  "$rootfs/run/recasaos-cgroup" "$rootfs/run/systemd"
sudo install -o root -g root -m 0000 /dev/null \
  "$rootfs/run/systemd/notify"
for cgroup_limit_file in memory.max memory.swap.max pids.max; do
  sudo install -o root -g root -m 0000 /dev/null \
    "$rootfs/run/recasaos-cgroup/$cgroup_limit_file"
done

sudo systemd-sysusers \
  "$repo_root/build/sysroot/usr/lib/sysusers.d/recasaos-public-files.conf"
service_uid="$(id -u recasaos-public)"
service_gid="$(id -g recasaos-public)"
[[ "$service_uid" -gt 0 && "$service_gid" -gt 0 ]] ||
  fail "system account is privileged"

sudo install -d -o root -g recasaos-public -m 0750 \
  "$share" "$nested_backing" "$rootfs/srv/public"
setup_hostile_storage_share
sudo install -d -o root -g recasaos-public -m 0750 "$nested_mount"
printf 'systemd isolation fixture\n' |
  sudo tee "$share/report.txt" >/dev/null
sudo truncate -s "$worker_load_bytes" "$share/worker-load.bin"
printf 'must remain covered by the nested mount\n' |
  sudo tee "$nested_mount/must-remain-covered.txt" >/dev/null
printf 'nested mount content must be rejected\n' |
  sudo tee "$nested_backing/nested-mount.txt" >/dev/null
sudo chown root:recasaos-public \
  "$share/report.txt" \
  "$share/worker-load.bin" \
  "$nested_mount/must-remain-covered.txt" \
  "$nested_backing/nested-mount.txt"
sudo chmod 0640 \
  "$share/report.txt" \
  "$share/worker-load.bin" \
  "$nested_mount/must-remain-covered.txt" \
  "$nested_backing/nested-mount.txt"
nested_mount_cleanup_required=1
sudo mount --bind "$nested_backing" "$nested_mount"
sudo chmod 0555 "$rootfs/proc" "$rootfs/sys"
sudo chmod 01777 "$rootfs/tmp" "$rootfs/var/tmp"
host_shm_sentinel="$(mktemp "${host_shm_sentinel_prefix}XXXXXX")"
[[ "$host_shm_sentinel" =~ ^/dev/shm/recasaos-public-files-ci-[0-9]+-[0-9]+\.[A-Za-z0-9]{6}$ ]] ||
  fail "mktemp returned an unsafe shared-memory sentinel: $host_shm_sentinel"
host_shm_sentinel_created=1
printf '%s\n' 'host shared-memory sentinel must remain hidden' \
  >"$host_shm_sentinel"
sudo chown root:root "$host_shm_sentinel"
sudo chmod 0600 "$host_shm_sentinel"

digest="$(printf '%s' "$test_bearer" | sha256sum | awk '{ print $1 }')"
printf 'recasaos-public-verifier-v1:sha256:%s\n' "$digest" |
  sudo tee "$verifier" >/dev/null
sudo chown root:root "$verifier"
sudo chmod 0600 "$verifier"
sudo install -o root -g root -m 0600 "$verifier" "$good_verifier"
[[ "$(sudo stat -c %s "$verifier")" == 100 ]] ||
  fail "test verifier has the wrong length"

CGO_ENABLED=0 GOOS=linux go build -trimpath -tags 'netgo osusergo' \
  -o "$production_binary" \
  ./cmd/recasaos-public-files
CGO_ENABLED=0 GOOS=linux go build -trimpath \
  -tags 'netgo osusergo recasaos_publicfiles_systemd_test' \
  -o "$systemd_test_binary" \
  ./cmd/recasaos-public-files
build_input_template=
build_input_template+='{{range .GoFiles}}{{$.ImportPath}} GoFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .CgoFiles}}{{$.ImportPath}} CgoFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .CFiles}}{{$.ImportPath}} CFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .CXXFiles}}{{$.ImportPath}} CXXFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .MFiles}}{{$.ImportPath}} MFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .HFiles}}{{$.ImportPath}} HFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .FFiles}}{{$.ImportPath}} FFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .SFiles}}{{$.ImportPath}} SFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .SwigFiles}}{{$.ImportPath}} SwigFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .SwigCXXFiles}}{{$.ImportPath}} SwigCXXFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .SysoFiles}}{{$.ImportPath}} SysoFiles {{.}}{{"\n"}}{{end}}'
build_input_template+='{{range .EmbedFiles}}{{$.ImportPath}} EmbedFiles {{.}}{{"\n"}}{{end}}'
production_build_inputs="$(
  CGO_ENABLED=0 GOOS=linux go list \
    -deps \
    -tags 'netgo osusergo' \
    -f "$build_input_template" \
    ./cmd/recasaos-public-files |
    LC_ALL=C sort -u
)" || fail "could not inspect production public-files build inputs"
production_gate_files="$(
  printf '%s\n' "$production_build_inputs" |
    awk '
      $1 == "github.com/IceWhaleTech/CasaOS/pkg/publicfiles" &&
        $2 == "GoFiles" &&
        $3 ~ /^worker_systemd_test_gate_(disabled|enabled)_linux\.go$/ {
        print $3
      }
    '
)"
[[ "$production_gate_files" == \
  worker_systemd_test_gate_disabled_linux.go ]] ||
  fail "production build selected unsafe systemd test gates: $production_gate_files"
systemd_test_build_inputs="$(
  CGO_ENABLED=0 GOOS=linux go list \
    -deps \
    -tags 'netgo osusergo recasaos_publicfiles_systemd_test' \
    -f "$build_input_template" \
    ./cmd/recasaos-public-files |
    LC_ALL=C sort -u
)" || fail "could not inspect tagged public-files build inputs"
systemd_test_gate_files="$(
  printf '%s\n' "$systemd_test_build_inputs" |
    awk '
      $1 == "github.com/IceWhaleTech/CasaOS/pkg/publicfiles" &&
        $2 == "GoFiles" &&
        $3 ~ /^worker_systemd_test_gate_(disabled|enabled)_linux\.go$/ {
        print $3
      }
    '
)"
[[ "$systemd_test_gate_files" == \
  worker_systemd_test_gate_enabled_linux.go ]] ||
  fail "tagged build selected unexpected systemd test gates: $systemd_test_gate_files"
production_shared_build_inputs="$(
  printf '%s\n' "$production_build_inputs" |
    awk '
      $1 == "github.com/IceWhaleTech/CasaOS/pkg/publicfiles" &&
        $2 == "GoFiles" &&
        $3 ~ /^worker_systemd_test_gate_(disabled|enabled)_linux\.go$/ {
        next
      }
      { print }
    '
)"
systemd_test_shared_build_inputs="$(
  printf '%s\n' "$systemd_test_build_inputs" |
    awk '
      $1 == "github.com/IceWhaleTech/CasaOS/pkg/publicfiles" &&
        $2 == "GoFiles" &&
        $3 ~ /^worker_systemd_test_gate_(disabled|enabled)_linux\.go$/ {
        next
      }
      { print }
    '
)"
[[ -n "$production_shared_build_inputs" &&
  "$production_shared_build_inputs" == "$systemd_test_shared_build_inputs" ]] ||
  fail "production and tagged binaries select different shared build inputs"
for built_binary in "$production_binary" "$systemd_test_binary"; do
  [[ -x "$built_binary" ]] ||
    fail "public-files build filesystem does not permit execution: $built_binary"
  file "$built_binary" | grep -q 'statically linked' ||
    fail "public-files binary is not static: $built_binary"
done
if cmp -s -- "$production_binary" "$systemd_test_binary"; then
  fail "systemd capacity binary is identical to the production build"
fi
if LC_ALL=C grep -aFq -- \
  'recasaos-systemd-test-event=' "$production_binary"; then
  fail "production binary contains CI-only systemd event diagnostics"
fi
LC_ALL=C grep -aFq -- \
  'recasaos-systemd-test-event=' "$systemd_test_binary" ||
  fail "tagged binary omitted CI-only systemd event diagnostics"
sudo install -o root -g root -m 0755 \
  "$production_binary" \
  "$rootfs/usr/bin/recasaos-public-files"

sudo install -o root -g root -m 0644 \
  "$repo_root/build/sysroot/usr/lib/systemd/system/$service_unit" \
  "$service_path"
sudo install -o root -g root -m 0644 \
  "$repo_root/build/sysroot/usr/lib/systemd/system/$socket_unit" \
  "$socket_path"
sudo install -d -o root -g root -m 0755 "$override_dir"
printf '%s\n' \
  '[Unit]' \
  'ConditionPathIsDirectory=' \
  "ConditionPathIsDirectory=$share" \
  'ConditionPathExists=/sys/fs/cgroup/cgroup.controllers' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.swap.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/pids.max' \
  "ConditionFileNotEmpty=$verifier" \
  "ConditionPathIsSymbolicLink=!$verifier" \
  'StartLimitIntervalSec=15s' \
  'StartLimitBurst=3' \
  '' \
  '[Service]' \
  "RootDirectory=$rootfs" \
  'BindReadOnlyPaths=' \
  "BindReadOnlyPaths=$share:/srv/public:rbind" \
  'BindReadOnlyPaths=/run/systemd/notify:/run/systemd/notify:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.max:/run/recasaos-cgroup/memory.max:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.swap.max:/run/recasaos-cgroup/memory.swap.max:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/pids.max:/run/recasaos-cgroup/pids.max:norbind' \
  'LoadCredential=' \
  "LoadCredential=recasaos-public-file-verifier:$verifier" \
  'RestartSec=1s' |
  sudo tee "$override_path" >/dev/null
sudo chmod 0644 "$override_path"
sudo install -d -o root -g root -m 0755 "$socket_override_dir"
printf '%s\n' \
  '[Unit]' \
  'ConditionPathIsDirectory=' \
  "ConditionPathIsDirectory=$share" \
  'ConditionPathExists=/sys/fs/cgroup/cgroup.controllers' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.swap.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/pids.max' \
  "ConditionFileNotEmpty=$verifier" \
  "ConditionPathIsSymbolicLink=!$verifier" |
  sudo tee "$socket_override_path" >/dev/null
sudo chmod 0644 "$socket_override_path"

sudo systemctl daemon-reload

"$repo_root/deploy/systemd/verify-public-files-units.sh" \
  "$service_path" \
  "$socket_path" \
  "$production_binary" \
  "$override_path" \
  "$socket_override_path"
require_unit_property "$service_unit" Type notify
require_unit_property "$service_unit" NotifyAccess main
require_unit_property "$service_unit" User recasaos-public
require_unit_property "$service_unit" Group recasaos-public
require_unit_property "$service_unit" RootDirectory "$rootfs"
require_unit_property "$service_unit" PrivateNetwork yes
require_unit_property "$service_unit" PrivateDevices yes
require_unit_property "$service_unit" PrivateMounts yes
require_unit_property "$service_unit" ProtectProc invisible
require_unit_property "$service_unit" ProcSubset pid
require_unit_property "$service_unit" ProtectSystem strict
require_unit_property "$service_unit" ProtectHome yes
require_unit_property "$service_unit" NoNewPrivileges yes
require_unit_property "$service_unit" LimitNOFILE 512
require_unit_property "$service_unit" TasksMax 256
require_unit_property "$service_unit" MemoryMax 536870912
require_unit_property "$service_unit" MemorySwapMax 0
require_unit_property "$service_unit" KillMode control-group

service_fragment="$(
  sudo systemctl show --property=FragmentPath --value "$service_unit"
)"
socket_fragment="$(
  sudo systemctl show --property=FragmentPath --value "$socket_unit"
)"
service_drop_ins="$(
  sudo systemctl show --property=DropInPaths --value "$service_unit"
)"
socket_drop_ins="$(
  sudo systemctl show --property=DropInPaths --value "$socket_unit"
)"
[[ "$(readlink -f -- "$service_fragment")" == \
  "$(readlink -f -- "$service_path")" ]] ||
  fail "systemd loaded an unexpected service fragment: $service_fragment"
[[ "$(readlink -f -- "$socket_fragment")" == \
  "$(readlink -f -- "$socket_path")" ]] ||
  fail "systemd loaded an unexpected socket fragment: $socket_fragment"
[[ "$service_drop_ins" == "$override_path" ]] ||
  fail "systemd loaded unexpected service drop-ins: $service_drop_ins"
[[ "$socket_drop_ins" == "$socket_override_path" ]] ||
  fail "systemd loaded unexpected socket drop-ins: $socket_drop_ins"

# The socket must not bind when the verifier is empty, the wrong type, or a
# symlink. ConditionFileNotEmpty follows symlinks, so the explicit negated
# ConditionPathIsSymbolicLink check is independently required.
sudo rm -f -- "$verifier"
assert_unsafe_verifier_skips_units "missing verifier"

sudo install -o root -g root -m 0600 "$good_verifier" "$verifier"
sudo truncate -s 0 "$verifier"
assert_unsafe_verifier_skips_units "empty verifier"

sudo rm -f -- "$verifier"
sudo install -d -o root -g root -m 0700 "$verifier"
assert_unsafe_verifier_skips_units "directory verifier"

sudo rmdir -- "$verifier"
sudo ln -s -- "$good_verifier" "$verifier"
assert_unsafe_verifier_skips_units "symlink verifier"

sudo rm -f -- "$verifier"
sudo install -o root -g root -m 0600 "$good_verifier" "$verifier"

sudo install -d -o "$runner_uid" -g "$runner_gid" -m 0755 "$management_dir"
printf 'management sentinel\n' >"$management_dir/health.txt"
printf 'must not be visible in the portal root\n' >"$management_dir/secret.txt"
sudo systemd-run --quiet --unit="$sentinel_unit" \
  --property=Type=exec \
  --property=Restart=always \
  --property=RestartSec=1s \
  --property=KillMode=control-group \
  /usr/bin/python3 -m http.server 39888 --bind 127.0.0.1 \
  --directory "$management_dir"
wait_until "management sentinel process" sentinel_is_active
sentinel_pid="$(
  sudo systemctl show --property=MainPID --value "$sentinel_unit"
)"
sentinel_invocation="$(
  sudo systemctl show --property=InvocationID --value "$sentinel_unit"
)"
[[ "$sentinel_pid" =~ ^[0-9]+$ && "$sentinel_pid" -gt 1 ]] ||
  fail "management sentinel has no process"
wait_until "management sentinel HTTP endpoint" sentinel_is_unchanged

sudo systemctl start "$socket_unit"
wait_until "public portal activation" page_is_ready
sudo systemctl is-active --quiet "$socket_unit"
sudo systemctl is-active --quiet "$service_unit"

portal_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"
[[ "$portal_pid" =~ ^[0-9]+$ && "$portal_pid" -gt 1 ]] ||
  fail "public-files service has no process"
portal_invocation="$(
  sudo systemctl show --property=InvocationID --value "$service_unit"
)"
[[ -n "$portal_invocation" ]] ||
  fail "public-files service has no invocation identity"
assert_service_cgroup_limits
cgroup_limit_view="/proc/$portal_pid/root/run/recasaos-cgroup"
sudo test -d "$cgroup_limit_view" ||
  fail "service cgroup limit view is missing or linked"
sudo test ! -L "$cgroup_limit_view" ||
  fail "service cgroup limit view is missing or linked"
for cgroup_limit_spec in \
  memory.max:536870912 \
  memory.swap.max:0 \
  pids.max:256
do
  cgroup_limit_name=${cgroup_limit_spec%%:*}
  cgroup_limit_expected=${cgroup_limit_spec#*:}
  cgroup_limit_path="$cgroup_limit_view/$cgroup_limit_name"
  sudo test -f "$cgroup_limit_path" ||
    fail "jailed runtime cgroup limit is missing or linked: $cgroup_limit_name"
  sudo test ! -L "$cgroup_limit_path" ||
    fail "jailed runtime cgroup limit is missing or linked: $cgroup_limit_name"
  [[ "$(sudo stat -fc %T "$cgroup_limit_path")" == cgroup2fs ]] ||
    fail "jailed runtime cgroup limit is not backed by cgroup v2: $cgroup_limit_name"
  [[ "$(sudo cat "$cgroup_limit_path")" == "$cgroup_limit_expected" ]] ||
    fail "jailed runtime sees an unexpected $cgroup_limit_name"
  sudo awk \
    -v expected_root="/system.slice/$service_unit/$cgroup_limit_name" \
    -v expected_target="/run/recasaos-cgroup/$cgroup_limit_name" '
      function has_option(options, wanted, count, values, option_index) {
        count = split(options, values, ",")
        for (option_index = 1; option_index <= count; option_index++)
          if (values[option_index] == wanted)
            return 1
        return 0
      }
      {
        separator = 0
        for (field_index = 7; field_index <= NF; field_index++)
          if ($field_index == "-") {
            separator = field_index
            break
          }
        if ($5 != expected_target)
          next
        matches++
        if ($4 != expected_root ||
            !has_option($6, "ro") ||
            has_option($6, "rw") ||
            separator == 0 ||
            $(separator + 1) != "cgroup2")
          invalid = 1
      }
      END { exit !(matches == 1 && !invalid) }
    ' "/proc/$portal_pid/mountinfo" ||
    fail "jailed runtime has an unexpected cgroup mount: $cgroup_limit_name"
done
notify_socket_view="/proc/$portal_pid/root/run/systemd/notify"
jailed_systemd_runtime_metadata="$(
  sudo stat -Lc '%u:%g:%a' "/proc/$portal_pid/root/run/systemd"
)"
case "$jailed_systemd_runtime_metadata" in
  0:0:555 | 0:0:755) ;;
  *)
    fail \
      "jailed systemd runtime directory metadata is unsafe: $jailed_systemd_runtime_metadata"
    ;;
esac
sudo test -S /run/systemd/notify ||
  fail "host systemd notification socket is missing"
sudo test -S "$notify_socket_view" ||
  fail "systemd notification socket is unavailable inside the service root"
host_notify_socket_identity="$(sudo stat -Lc '%d:%i' /run/systemd/notify)"
jailed_notify_socket_identity="$(sudo stat -Lc '%d:%i' "$notify_socket_view")"
[[ "$host_notify_socket_identity" == "$jailed_notify_socket_identity" ]] ||
  fail "jailed systemd notification socket does not match the host socket"
sudo awk '
  function has_option(options, wanted, count, values, option_index) {
    count = split(options, values, ",")
    for (option_index = 1; option_index <= count; option_index++)
      if (values[option_index] == wanted)
        return 1
    return 0
  }
  $5 == "/run/systemd/notify" {
    matches++
    if (!has_option($6, "ro") || has_option($6, "rw"))
      invalid = 1
  }
  END { exit !(matches == 1 && !invalid) }
' "/proc/$portal_pid/mountinfo" ||
  fail "jailed systemd notification socket is not one exact read-only mount"
sudo awk -v uid="$service_uid" -v gid="$service_gid" '
  BEGIN {
    uid_ok = gid_ok = groups_ok = umask_ok = caps_ok = nnp_ok = seccomp_ok = 0
    cap_count = 0
  }
  $1 == "Uid:" {
    uid_ok = ($2 == uid && $3 == uid && $4 == uid && $5 == uid)
  }
  $1 == "Gid:" {
    gid_ok = ($2 == gid && $3 == gid && $4 == gid && $5 == gid)
  }
  $1 == "Groups:" {
    groups_ok = 1
    for (i = 2; i <= NF; i++)
      if ($i != gid)
        groups_ok = 0
  }
  $1 == "Umask:" { umask_ok = ($2 == "0077") }
  $1 ~ /^Cap(Inh|Prm|Eff|Bnd|Amb):$/ {
    cap_count++
    if ($2 != "0000000000000000")
      caps_bad = 1
  }
  $1 == "NoNewPrivs:" { nnp_ok = ($2 == 1) }
  $1 == "Seccomp:" { seccomp_ok = ($2 == 2) }
  $1 == "Seccomp_filters:" { filters_seen = 1; filters_ok = ($2 >= 1) }
  END {
    caps_ok = (cap_count == 5 && !caps_bad)
    if (!uid_ok || !gid_ok || !groups_ok || !umask_ok || !caps_ok ||
        !nnp_ok || !seccomp_ok || (filters_seen && !filters_ok))
      exit 1
  }
' "/proc/$portal_pid/status" ||
  fail "runtime UID/GID/capability/seccomp invariants are not satisfied"
[[ "$(sudo stat -Lc %u "/proc/$portal_pid/mem")" == 0 ]] ||
  fail "portal process memory remains owned by the service identity"
if sudo -u recasaos-public -- /bin/bash -c \
  'exec 3<"$1"' bash "/proc/$portal_pid/mem" 2>/dev/null; then
  fail "same-UID process can open the portal process memory"
fi

root_net_ns="$(sudo stat -Lc %i /proc/1/ns/net)"
portal_net_ns="$(sudo stat -Lc %i "/proc/$portal_pid/ns/net")"
root_mount_ns="$(sudo stat -Lc %i /proc/1/ns/mnt)"
portal_mount_ns="$(sudo stat -Lc %i "/proc/$portal_pid/ns/mnt")"
[[ "$portal_net_ns" != "$root_net_ns" ]] ||
  fail "service still shares PID 1's network namespace"
[[ "$portal_mount_ns" != "$root_mount_ns" ]] ||
  fail "service still shares PID 1's mount namespace"
if sudo nsenter --target "$portal_pid" --net \
  curl -q -sS --max-time 1 http://127.0.0.1:39888/health.txt \
  >/dev/null 2>&1; then
  fail "private network namespace can reach the host management sentinel"
fi

sudo test -r "/proc/$portal_pid/root/srv/public/report.txt" ||
  fail "read-only share is not visible in the service root"
if sudo touch "/proc/$portal_pid/root/srv/public/forbidden" 2>/dev/null; then
  fail "service share is writable"
fi
if sudo chmod 0666 "/proc/$portal_pid/root/srv/public/report.txt" 2>/dev/null; then
  fail "service share metadata is writable"
fi
for host_device in /dev/fuse /dev/kvm /dev/net/tun; do
  sudo test ! -e "/proc/$portal_pid/root$host_device" ||
    fail "host device is visible in the service root: $host_device"
done
if sudo find "/proc/$portal_pid/root/dev" -xdev -type b -print -quit |
  grep -q .; then
  fail "a block device is visible in the service root"
fi
sudo test ! -e "/proc/$portal_pid/root/var/lib/casaos" ||
  fail "CasaOS state is visible in the service root"
sudo test ! -e "/proc/$portal_pid/root$workspace" ||
  fail "host CI management workspace is visible in the service root"
sudo test -d "/proc/$portal_pid/root/proc/self/fd" ||
  fail "procfd is unavailable in the service root"
proc_mount="$(
  sudo awk '$5 == "/proc" { print; exit }' "/proc/$portal_pid/mountinfo"
)"
[[ "$proc_mount" == *"subset=pid"* ]] ||
  fail "service procfs is not restricted to the PID subset"
[[ "$proc_mount" == *"hidepid=invisible"* ||
  "$proc_mount" == *"hidepid=2"* ]] ||
  fail "service procfs does not hide other users' processes"

assert_systemd_credential_for_pid "$portal_pid"
assert_service_api_vfs_isolation "$portal_pid"

listener_count="$(
  sudo ss -H -ltn |
    awk '$4 == "127.0.0.1:39777" { count++ } END { print count + 0 }'
)"
[[ "$listener_count" == 1 ]] ||
  fail "expected exactly one literal-loopback public listener"

unauthorized_status="$(
  curl -q -sS -o /dev/null -w '%{http_code}' \
    http://127.0.0.1:39777/public-files/api/list
)"
[[ "$unauthorized_status" == 401 ]] ||
  fail "unauthenticated listing did not return 401"

printf 'Authorization: Bearer %s\n' "$test_bearer" |
  curl -q -sS -H @- \
    'http://127.0.0.1:39777/public-files/api/list?path=' \
    -o "$response_file"
grep -q '"name":"report.txt"' "$response_file" ||
  fail "authorized listing omitted the fixture"
if grep -Eq 'covered|nested-mount|must-remain-covered' "$response_file"; then
  fail "authorized listing exposed a nested mount or covered host content"
fi
if grep -Fq "$workspace" "$response_file"; then
  fail "authorized listing exposed a host path"
fi

printf 'Authorization: Bearer %s\n' "$test_bearer" |
  curl -q -sS -H @- \
    'http://127.0.0.1:39777/public-files/api/file?path=report.txt' \
    -o "$response_file"
printf '%s\n' 'systemd isolation fixture' |
  cmp - "$response_file" ||
  fail "downloaded bytes differ from the approved file"

sudo cmp -s -- "/proc/$portal_pid/exe" "$production_binary" ||
  fail "running production portal bytes differ from the reviewed binary"
production_worker_deadline=$((SECONDS + 15))
start_slow_download
wait_until_before "production slow download response" \
  "$production_worker_deadline" \
  slow_download_is_ready \
  "$latest_slow_download_pid" \
  "$latest_slow_download_ready_file" \
  "$latest_slow_download_failure_file" \
  "$latest_slow_download_start_time"
wait_until_before "one production storage worker" \
  "$production_worker_deadline" \
  storage_worker_count_is 1
production_worker_pid="$(storage_worker_pids)"
[[ "$production_worker_pid" =~ ^[0-9]+$ && "$production_worker_pid" -gt 1 ]] ||
  fail "production probe did not retain exactly one storage worker"
production_worker_start_time="$(
  process_start_time "$production_worker_pid"
)" || fail "could not capture production storage worker identity"
assert_storage_worker_address_space_limit \
  "$production_worker_pid" \
  "$production_worker_start_time" \
  production
cleanup_background_downloads
production_cleanup_deadline=$((SECONDS + 10))
wait_until_before "production storage worker pidfd cancellation" \
  "$production_cleanup_deadline" \
  process_identity_is_gone \
  "$production_worker_pid" \
  "$production_worker_start_time"
wait_until_before "production storage worker reap" \
  "$production_cleanup_deadline" \
  storage_worker_count_is 0

activate_public_binary \
  "$systemd_test_binary" \
  "systemd capacity binary activation"
sudo cmp -s -- "/proc/$portal_pid/exe" "$systemd_test_binary" ||
  fail "running systemd-test portal bytes differ from the reviewed binary"
wait_until "storage workers before bounded load" storage_worker_count_is 0
capture_capacity_journal_cursor
start_cgroup_memory_sampler
worker_capacity_deadline=$((SECONDS + worker_capacity_window_seconds))
for _ in {1..8}; do
  start_slow_download
done
wait_until_before "eight slow download responses" \
  "$worker_capacity_deadline" \
  slow_downloads_are_healthy
wait_until_before "eight bounded storage workers" \
  "$worker_capacity_deadline" \
  storage_worker_count_is 8
wait_until_before "eight stopped storage workers" \
  "$worker_capacity_deadline" \
  storage_workers_are_stopped 8
mapfile -t bounded_worker_pids < <(storage_worker_pids)
[[ "${#bounded_worker_pids[@]}" == 8 ]] ||
  fail "bounded load did not retain exactly eight worker identities"
for bounded_worker_pid in "${bounded_worker_pids[@]}"; do
  bounded_worker_start_time="$(
    process_start_time "$bounded_worker_pid"
  )" || fail "could not capture bounded worker identity"
  bounded_worker_start_times+=("$bounded_worker_start_time")
done

install -m 0600 /dev/null "$ninth_response_headers"
ninth_status="$(
  printf 'Authorization: Bearer %s\n' "$test_bearer" |
    curl -q -sS --max-time 5 -H @- \
      -D "$ninth_response_headers" \
      -o /dev/null \
      -w '%{http_code}' \
      'http://127.0.0.1:39777/public-files/api/file?path=worker-load.bin'
)"
[[ "$ninth_status" == 503 ]] ||
  fail "ninth concurrent storage request returned $ninth_status, want 503"
[[ "$(
  awk '
    {
      line = $0
      sub(/\r$/, "", line)
      separator = index(line, ":")
      if (separator == 0) {
        next
      }
      name = tolower(substr(line, 1, separator - 1))
      if (name != "retry-after") {
        next
      }
      count++
      value = substr(line, separator + 1)
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      if (value != "5") {
        invalid++
      }
    }
    END { printf "%d:%d\n", count + 0, invalid + 0 }
  ' "$ninth_response_headers"
)" == 1:0 ]] ||
  fail "ninth concurrent storage request lacked one exact Retry-After value 5"
worker_capacity_evidence_deadline=$((
  SECONDS + worker_capacity_evidence_window_seconds
))
wait_until_before "storage worker capacity event chain" \
  "$worker_capacity_evidence_deadline" \
  capacity_phase_events_are_complete
listener_inode="$(
  sudo awk \
    '$2 == "0100007F:9B61" && $4 == "0A" { print $10; exit }' \
    /proc/net/tcp
)"
[[ "$listener_inode" =~ ^[0-9]+$ ]] ||
  fail "could not resolve the public listener inode"
assert_bounded_storage_worker_runtime_boundaries
stop_cgroup_memory_sampler

tasks_current="$(
  sudo systemctl show --property=TasksCurrent --value "$service_unit"
)"
memory_current="$(
  sudo systemctl show --property=MemoryCurrent --value "$service_unit"
)"
if ! memory_peak="$(
  sudo systemctl show --property=MemoryPeak --value "$service_unit" \
    2>/dev/null
)"; then
  memory_peak=
fi
[[ "$tasks_current" =~ ^[0-9]+$ && "$tasks_current" -le 224 ]] ||
  fail "eight-worker TasksCurrent=$tasks_current leaves insufficient headroom"
[[ "$memory_current" =~ ^[0-9]+$ && "$memory_current" -le 469762048 ]] ||
  fail "eight-worker MemoryCurrent=$memory_current leaves insufficient headroom"
[[ "$sampled_memory_peak" =~ ^[0-9]+$ &&
  "$sampled_memory_peak" -le 469762048 ]] ||
  fail "sampled eight-worker memory peak=$sampled_memory_peak leaves insufficient headroom"
if [[ "$memory_peak" =~ ^[0-9]+$ ]]; then
  [[ "$memory_peak" -le 469762048 ]] ||
    fail "eight-worker MemoryPeak=$memory_peak leaves insufficient headroom"
  [[ "$memory_peak" -ge "$sampled_memory_peak" ]] ||
    fail "systemd MemoryPeak=$memory_peak is below sampled peak=$sampled_memory_peak"
elif [[ "${RECASAOS_SYSTEMD_TEST_TARGET:-}" != \
  debian-11-systemd-247-qemu ]]; then
  fail "systemd MemoryPeak is unavailable on a target that requires it"
else
  printf 'systemd 247 MemoryPeak unavailable; reviewed memory.current sampler peak=%s\n' \
    "$sampled_memory_peak"
fi

worker_pre_cancellation_budget=$((worker_capacity_window_seconds + 10))
((SECONDS < worker_capacity_deadline + 10)) ||
  fail \
    "bounded worker phase exceeded its ${worker_pre_cancellation_budget}-second pre-cancellation budget"
worker_cancellation_deadline=$((worker_capacity_deadline + 13))
((SECONDS < worker_cancellation_deadline)) ||
  fail "bounded worker phase left no pre-timeout cancellation window"
cleanup_background_downloads
for bounded_worker_index in "${!bounded_worker_pids[@]}"; do
  bounded_worker_pid="${bounded_worker_pids[$bounded_worker_index]}"
  wait_until_before "storage worker $bounded_worker_pid pidfd cancellation" \
    "$worker_cancellation_deadline" \
    process_identity_is_gone \
    "$bounded_worker_pid" \
    "${bounded_worker_start_times[$bounded_worker_index]}"
done
bounded_worker_pids=()
bounded_worker_start_times=()
wait_until_before "storage worker reap after bounded load" \
  "$worker_cancellation_deadline" \
  storage_worker_count_is 0
activate_public_binary \
  "$production_binary" \
  "production binary restoration after capacity test"

if [[ "$hostile_storage_test_enabled" == 1 ]]; then
  wait_until "storage workers before hostile-storage test" \
    storage_worker_count_is 0
  sudo sync
  printf '3\n' | sudo tee /proc/sys/vm/drop_caches >/dev/null
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping was suspended before the test"
  hostile_storage_nbd_server_is_exact ||
    fail "hostile-storage NBD server identity changed before fault injection"
  hostile_storage_nbd_listener_is_exact ||
    fail "hostile-storage NBD loopback listener changed before fault injection"
  hostile_storage_nbd_server_stopped=1
  signal_exact_hostile_storage_nbd_server 19 ||
    fail "could not stop the exact hostile-storage NBD server"
  hostile_nbd_stop_deadline=$((SECONDS + 5))
  wait_until_before "hostile-storage NBD server stop" \
    "$hostile_nbd_stop_deadline" \
    hostile_storage_nbd_server_state_is T
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping, rather than its NBD server, was suspended"

  hostile_blocked_deadline=$((SECONDS + 8))
  for _ in {1..4}; do
    start_hostile_storage_client
  done
  wait_until_before "four live hostile-storage clients" \
    "$hostile_blocked_deadline" \
    hostile_storage_clients_are_live
  wait_until_before "four hostile-storage workers" \
    "$hostile_blocked_deadline" \
    storage_worker_count_is 4
  wait_until_before "four real D-state storage workers" \
    "$hostile_blocked_deadline" \
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

  hostile_timeout_deadline=$((SECONDS + 18))
  wait_until_before "four bounded hostile-storage timeouts" \
    "$hostile_timeout_deadline" \
    hostile_storage_clients_are_complete
  assert_hostile_storage_client_responses
  assert_hostile_storage_worker_boundaries kill-pending "$portal_pid"
  [[ "$(storage_worker_count)" == 4 ]] ||
    fail "hostile-storage timeout did not retain exactly four D-state workers"

  hostile_quarantine_headers="${workspace}/hostile-quarantine.headers"
  hostile_quarantine_body="${workspace}/hostile-quarantine.body"
  for quarantine_path in \
    "$hostile_quarantine_headers" "$hostile_quarantine_body"
  do
    [[ ! -e "$quarantine_path" && ! -L "$quarantine_path" ]] ||
      fail "hostile-storage quarantine response path already exists"
    install -m 0600 /dev/null "$quarantine_path"
  done
  hostile_quarantine_started=$SECONDS
  hostile_quarantine_status="$(
    printf 'Authorization: Bearer %s\n' "$test_bearer" |
      curl -q -sS \
        --connect-timeout 2 \
        --max-time 5 \
        -H @- \
        -H 'Connection: close' \
        -D "$hostile_quarantine_headers" \
        -o "$hostile_quarantine_body" \
        -w '%{http_code}' \
        'http://127.0.0.1:39777/public-files/api/list?path='
  )"
  hostile_quarantine_elapsed=$((SECONDS - hostile_quarantine_started))
  [[ "$hostile_quarantine_status" == 503 &&
    "$hostile_quarantine_elapsed" -le 5 ]] ||
    fail \
      "quarantine admission returned $hostile_quarantine_status after ${hostile_quarantine_elapsed}s"
  [[ "$(<"$hostile_quarantine_body")" == \
    '{"error":"storage capacity unavailable"}' ]] ||
    fail "quarantine admission returned an unexpected body"
  [[ "$(
    awk '
      {
        line = $0
        sub(/\r$/, "", line)
        separator = index(line, ":")
        if (separator == 0)
          next
        name = tolower(substr(line, 1, separator - 1))
        if (name != "retry-after")
          next
        count++
        value = substr(line, separator + 1)
        sub(/^[[:space:]]+/, "", value)
        sub(/[[:space:]]+$/, "", value)
        if (value != "5")
          invalid++
      }
      END { printf "%d:%d\n", count + 0, invalid + 0 }
    ' "$hostile_quarantine_headers"
  )" == 1:0 ]] ||
    fail "quarantine admission lacked one exact Retry-After value 5"
  if grep -aFq -- 'rc1_' \
    "$hostile_quarantine_headers" "$hostile_quarantine_body"; then
    fail "quarantine response retained a bearer-shaped value"
  fi
  [[ "$(storage_worker_count)" == 4 ]] ||
    fail "quarantine admission started an additional storage worker"
  assert_hostile_storage_worker_boundaries kill-pending "$portal_pid"

  hostile_tasks_current="$(
    sudo systemctl show --property=TasksCurrent --value "$service_unit"
  )"
  hostile_memory_current="$(
    sudo systemctl show --property=MemoryCurrent --value "$service_unit"
  )"
  [[ "$hostile_tasks_current" =~ ^[0-9]+$ &&
    "$hostile_tasks_current" -le 224 ]] ||
    fail \
      "D-state TasksCurrent=$hostile_tasks_current leaves insufficient headroom"
  [[ "$hostile_memory_current" =~ ^[0-9]+$ &&
    "$hostile_memory_current" -le 469762048 ]] ||
    fail \
      "D-state MemoryCurrent=$hostile_memory_current leaves insufficient headroom"
  assert_service_cgroup_limits
  wait_until "unchanged management sentinel during D-state" \
    sentinel_is_unchanged

  hostile_old_portal_pid=$portal_pid
  hostile_old_portal_invocation=$portal_invocation
  hostile_old_portal_start_time="$(
    process_start_time "$hostile_old_portal_pid"
  )" || fail "could not capture the pre-restart portal identity"
  sudo systemctl restart --no-block "$service_unit"
  hostile_restart_pending_deadline=$((SECONDS + 8))
  wait_until_before "old portal exit during D-state restart" \
    "$hostile_restart_pending_deadline" \
    process_identity_is_gone \
    "$hostile_old_portal_pid" \
    "$hostile_old_portal_start_time"
  wait_until_before "service deactivation behind D-state workers" \
    "$hostile_restart_pending_deadline" \
    service_is_deactivating
  assert_hostile_storage_worker_boundaries kill-pending 1
  wait_until "unchanged management sentinel during pending restart" \
    sentinel_is_unchanged
  hostile_storage_nbd_server_state_is T ||
    fail "hostile-storage NBD server resumed without operator action"
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping changed during the NBD fault"

  signal_exact_hostile_storage_nbd_server 18 ||
    fail "could not resume the exact hostile-storage NBD server"
  hostile_nbd_resume_deadline=$((SECONDS + 5))
  wait_until_before "hostile-storage NBD server resume" \
    "$hostile_nbd_resume_deadline" \
    hostile_storage_nbd_server_is_resumed
  hostile_storage_nbd_server_stopped=0
  hostile_recovery_deadline=$((SECONDS + 30))
  for hostile_worker_index in "${!hostile_worker_pids[@]}"; do
    wait_until_before \
      "hostile-storage worker ${hostile_worker_pids[$hostile_worker_index]} reap" \
      "$hostile_recovery_deadline" \
      process_identity_is_gone \
      "${hostile_worker_pids[$hostile_worker_index]}" \
      "${hostile_worker_start_times[$hostile_worker_index]}"
  done
  wait_until_before "public service recovery after hostile storage" \
    "$hostile_recovery_deadline" \
    service_has_new_pid
  wait_until_before "public portal recovery after hostile storage" \
    "$hostile_recovery_deadline" \
    page_is_ready
  portal_pid="$(
    sudo systemctl show --property=MainPID --value "$service_unit"
  )"
  portal_invocation="$(
    sudo systemctl show --property=InvocationID --value "$service_unit"
  )"
  [[ "$portal_pid" =~ ^[0-9]+$ && "$portal_pid" -gt 1 &&
    "$portal_pid" != "$hostile_old_portal_pid" &&
    -n "$portal_invocation" &&
    "$portal_invocation" != "$hostile_old_portal_invocation" ]] ||
    fail "hostile-storage recovery did not create a new portal invocation"
  hostile_worker_pids=()
  hostile_worker_start_times=()
  wait_until "storage workers after hostile-storage recovery" \
    storage_worker_count_is 0

  printf 'Authorization: Bearer %s\n' "$test_bearer" |
    curl -q -sS -H @- \
      'http://127.0.0.1:39777/public-files/api/file?path=report.txt' \
      -o "$response_file"
  printf '%s\n' 'systemd isolation fixture' |
    cmp - "$response_file" ||
    fail "post-D-state downloaded bytes differ from the approved file"
  assert_service_cgroup_limits
  assert_systemd_credential_for_pid "$portal_pid"
  assert_service_api_vfs_isolation "$portal_pid"
  wait_until "unchanged management sentinel after hostile-storage recovery" \
    sentinel_is_unchanged
  printf \
    'real loopback-NBD D-state recovery passed: workers=4 tasks=%s memory=%s\n' \
    "$hostile_tasks_current" "$hostile_memory_current"

  wait_until "storage workers before FUSE hostile-storage test" \
    storage_worker_count_is 0
  sudo sync
  printf '3\n' | sudo tee /proc/sys/vm/drop_caches >/dev/null
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping was suspended before the FUSE test"
  hostile_storage_fuse_daemon_is_exact ||
    fail "hostile-storage FUSE daemon identity changed before fault injection"
  hostile_storage_fuse_daemon_is_resumed ||
    fail "hostile-storage FUSE daemon was not runnable before fault injection"
  [[ "$(hostile_storage_fuse_waiting_value)" == 0 ]] ||
    fail "hostile-storage FUSE connection was not idle before fault injection"
  hostile_storage_nbd_server_is_exact ||
    fail "hostile-storage NBD server identity changed before the FUSE fault"
  hostile_storage_nbd_server_is_resumed ||
    fail "hostile-storage NBD server was not runnable before the FUSE fault"
  hostile_storage_nbd_listener_is_exact ||
    fail "hostile-storage NBD listener changed before the FUSE fault"

  hostile_storage_fuse_daemon_stopped=1
  signal_exact_hostile_storage_fuse_daemon 19 ||
    fail "could not stop the exact hostile-storage FUSE daemon"
  hostile_fuse_stop_deadline=$((SECONDS + 5))
  wait_until_before "hostile-storage FUSE daemon stop" \
    "$hostile_fuse_stop_deadline" \
    hostile_storage_fuse_daemon_state_is T
  hostile_storage_nbd_server_is_resumed ||
    fail "FUSE fault unexpectedly stopped the hostile-storage NBD server"
  hostile_storage_nbd_listener_is_exact ||
    fail "FUSE fault changed the hostile-storage NBD listener"
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping, rather than its FUSE daemon, was suspended"

  hostile_fuse_blocked_deadline=$((SECONDS + 8))
  for _ in {1..4}; do
    start_hostile_storage_client
  done
  wait_until_before "four live FUSE hostile-storage clients" \
    "$hostile_fuse_blocked_deadline" \
    hostile_storage_clients_are_live
  wait_until_before "FUSE kernel waiting request" \
    "$hostile_fuse_blocked_deadline" \
    hostile_storage_fuse_has_waiting_request
  wait_until_before "four FUSE hostile-storage workers" \
    "$hostile_fuse_blocked_deadline" \
    storage_worker_count_is 4
  wait_until_before "four real FUSE-backed D-state storage workers" \
    "$hostile_fuse_blocked_deadline" \
    storage_workers_are_in_d_state 4
  mapfile -t hostile_worker_pids < <(storage_worker_pids)
  [[ "${#hostile_worker_pids[@]}" == 4 ]] ||
    fail "FUSE hostile-storage load did not retain exactly four workers"
  for hostile_worker_pid in "${hostile_worker_pids[@]}"; do
    hostile_worker_start_time="$(
      process_start_time "$hostile_worker_pid"
    )" || fail "could not capture FUSE hostile-storage worker identity"
    hostile_worker_start_times+=("$hostile_worker_start_time")
  done
  assert_hostile_storage_worker_boundaries blocked "$portal_pid"
  hostile_storage_fuse_has_waiting_request ||
    fail "FUSE kernel waiting evidence disappeared during blocked inspection"
  hostile_storage_nbd_server_is_resumed ||
    fail "NBD server was not runnable during the FUSE-backed D-state fault"
  hostile_storage_nbd_listener_is_exact ||
    fail "NBD listener changed during the FUSE-backed D-state fault"
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping changed during the FUSE fault"
  hostile_storage_clients_are_live ||
    fail "FUSE hostile-storage clients exited during blocked worker inspection"

  hostile_fuse_timeout_deadline=$((SECONDS + 18))
  wait_until_before "four bounded FUSE hostile-storage timeouts" \
    "$hostile_fuse_timeout_deadline" \
    hostile_storage_clients_are_complete
  assert_hostile_storage_client_responses
  assert_hostile_storage_worker_boundaries kill-pending "$portal_pid"
  [[ "$(storage_worker_count)" == 4 ]] ||
    fail "FUSE hostile-storage timeout did not retain exactly four D-state workers"
  hostile_storage_fuse_has_waiting_request ||
    fail "FUSE kernel waiting evidence disappeared after bounded timeouts"

  hostile_fuse_quarantine_headers="${workspace}/hostile-fuse-quarantine.headers"
  hostile_fuse_quarantine_body="${workspace}/hostile-fuse-quarantine.body"
  for quarantine_path in \
    "$hostile_fuse_quarantine_headers" "$hostile_fuse_quarantine_body"
  do
    [[ ! -e "$quarantine_path" && ! -L "$quarantine_path" ]] ||
      fail "FUSE hostile-storage quarantine response path already exists"
    install -m 0600 /dev/null "$quarantine_path"
  done
  hostile_fuse_quarantine_started=$SECONDS
  hostile_fuse_quarantine_status="$(
    printf 'Authorization: Bearer %s\n' "$test_bearer" |
      curl -q -sS \
        --connect-timeout 2 \
        --max-time 5 \
        -H @- \
        -H 'Connection: close' \
        -D "$hostile_fuse_quarantine_headers" \
        -o "$hostile_fuse_quarantine_body" \
        -w '%{http_code}' \
        'http://127.0.0.1:39777/public-files/api/list?path='
  )"
  hostile_fuse_quarantine_elapsed=$((
    SECONDS - hostile_fuse_quarantine_started
  ))
  [[ "$hostile_fuse_quarantine_status" == 503 &&
    "$hostile_fuse_quarantine_elapsed" -le 5 ]] ||
    fail \
      "FUSE quarantine admission returned $hostile_fuse_quarantine_status after ${hostile_fuse_quarantine_elapsed}s"
  [[ "$(<"$hostile_fuse_quarantine_body")" == \
    '{"error":"storage capacity unavailable"}' ]] ||
    fail "FUSE quarantine admission returned an unexpected body"
  [[ "$(
    awk '
      {
        line = $0
        sub(/\r$/, "", line)
        separator = index(line, ":")
        if (separator == 0)
          next
        name = tolower(substr(line, 1, separator - 1))
        if (name != "retry-after")
          next
        count++
        value = substr(line, separator + 1)
        sub(/^[[:space:]]+/, "", value)
        sub(/[[:space:]]+$/, "", value)
        if (value != "5")
          invalid++
      }
      END { printf "%d:%d\n", count + 0, invalid + 0 }
    ' "$hostile_fuse_quarantine_headers"
  )" == 1:0 ]] ||
    fail "FUSE quarantine admission lacked one exact Retry-After value 5"
  if grep -aFq -- 'rc1_' \
    "$hostile_fuse_quarantine_headers" "$hostile_fuse_quarantine_body"; then
    fail "FUSE quarantine response retained a bearer-shaped value"
  fi
  [[ "$(storage_worker_count)" == 4 ]] ||
    fail "FUSE quarantine admission started an additional storage worker"
  assert_hostile_storage_worker_boundaries kill-pending "$portal_pid"
  wait_until "static portal during FUSE storage quarantine" page_is_ready

  hostile_fuse_tasks_current="$(
    sudo systemctl show --property=TasksCurrent --value "$service_unit"
  )"
  hostile_fuse_memory_current="$(
    sudo systemctl show --property=MemoryCurrent --value "$service_unit"
  )"
  [[ "$hostile_fuse_tasks_current" =~ ^[0-9]+$ &&
    "$hostile_fuse_tasks_current" -le 224 ]] ||
    fail \
      "FUSE D-state TasksCurrent=$hostile_fuse_tasks_current leaves insufficient headroom"
  [[ "$hostile_fuse_memory_current" =~ ^[0-9]+$ &&
    "$hostile_fuse_memory_current" -le 469762048 ]] ||
    fail \
      "FUSE D-state MemoryCurrent=$hostile_fuse_memory_current leaves insufficient headroom"
  assert_service_cgroup_limits
  wait_until "unchanged management sentinel during FUSE D-state" \
    sentinel_is_unchanged

  hostile_fuse_old_portal_pid=$portal_pid
  hostile_fuse_old_portal_invocation=$portal_invocation
  hostile_fuse_old_portal_start_time="$(
    process_start_time "$hostile_fuse_old_portal_pid"
  )" || fail "could not capture the pre-FUSE-restart portal identity"
  sudo systemctl restart --no-block "$service_unit"
  hostile_fuse_restart_pending_deadline=$((SECONDS + 8))
  wait_until_before "old portal exit during FUSE D-state restart" \
    "$hostile_fuse_restart_pending_deadline" \
    process_identity_is_gone \
    "$hostile_fuse_old_portal_pid" \
    "$hostile_fuse_old_portal_start_time"
  wait_until_before "service deactivation behind FUSE D-state workers" \
    "$hostile_fuse_restart_pending_deadline" \
    service_is_deactivating
  assert_hostile_storage_worker_boundaries kill-pending 1
  wait_until "unchanged management sentinel during pending FUSE restart" \
    sentinel_is_unchanged
  hostile_storage_fuse_daemon_state_is T ||
    fail "hostile-storage FUSE daemon resumed without operator action"
  hostile_storage_fuse_has_waiting_request ||
    fail "FUSE kernel waiting evidence disappeared during pending restart"
  hostile_storage_nbd_server_is_resumed ||
    fail "NBD server stopped during the pending FUSE restart"
  hostile_storage_nbd_listener_is_exact ||
    fail "NBD listener changed during the pending FUSE restart"
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping changed during the pending FUSE restart"

  signal_exact_hostile_storage_fuse_daemon 18 ||
    fail "could not resume the exact hostile-storage FUSE daemon"
  hostile_fuse_resume_deadline=$((SECONDS + 10))
  wait_until_before "hostile-storage FUSE daemon and request recovery" \
    "$hostile_fuse_resume_deadline" \
    hostile_storage_fuse_is_recovered
  hostile_storage_fuse_daemon_stopped=0
  hostile_fuse_recovery_deadline=$((SECONDS + 30))
  for hostile_worker_index in "${!hostile_worker_pids[@]}"; do
    wait_until_before \
      "FUSE hostile-storage worker ${hostile_worker_pids[$hostile_worker_index]} reap" \
      "$hostile_fuse_recovery_deadline" \
      process_identity_is_gone \
      "${hostile_worker_pids[$hostile_worker_index]}" \
      "${hostile_worker_start_times[$hostile_worker_index]}"
  done
  wait_until_before "public service recovery after FUSE hostile storage" \
    "$hostile_fuse_recovery_deadline" \
    service_has_new_pid
  wait_until_before "public portal recovery after FUSE hostile storage" \
    "$hostile_fuse_recovery_deadline" \
    page_is_ready
  portal_pid="$(
    sudo systemctl show --property=MainPID --value "$service_unit"
  )"
  portal_invocation="$(
    sudo systemctl show --property=InvocationID --value "$service_unit"
  )"
  [[ "$portal_pid" =~ ^[0-9]+$ && "$portal_pid" -gt 1 &&
    "$portal_pid" != "$hostile_fuse_old_portal_pid" &&
    -n "$portal_invocation" &&
    "$portal_invocation" != "$hostile_fuse_old_portal_invocation" ]] ||
    fail "FUSE hostile-storage recovery did not create a new portal invocation"
  hostile_worker_pids=()
  hostile_worker_start_times=()
  wait_until "storage workers after FUSE hostile-storage recovery" \
    storage_worker_count_is 0

  printf 'Authorization: Bearer %s\n' "$test_bearer" |
    curl -q -sS -H @- \
      'http://127.0.0.1:39777/public-files/api/file?path=report.txt' \
      -o "$response_file"
  printf '%s\n' 'systemd isolation fixture' |
    cmp - "$response_file" ||
    fail "post-FUSE-D-state downloaded bytes differ from the approved file"
  hostile_storage_fuse_is_recovered ||
    fail "FUSE connection was not idle after byte-correct recovery"
  hostile_storage_nbd_server_is_exact ||
    fail "NBD server identity changed after FUSE recovery"
  hostile_storage_nbd_listener_is_exact ||
    fail "NBD listener changed after FUSE recovery"
  [[ "$(hostile_storage_suspended_value)" == 0 ]] ||
    fail "hostile-storage mapping changed after FUSE recovery"
  assert_service_cgroup_limits
  assert_systemd_credential_for_pid "$portal_pid"
  assert_service_api_vfs_isolation "$portal_pid"
  wait_until \
    "unchanged management sentinel after FUSE hostile-storage recovery" \
    sentinel_is_unchanged
  printf \
    'real FUSE-backed NBD D-state recovery passed: workers=4 waiting>=1 tasks=%s memory=%s\n' \
    "$hostile_fuse_tasks_current" "$hostile_fuse_memory_current"
fi

for blocked_file in \
  covered/must-remain-covered.txt \
  covered/nested-mount.txt
do
  blocked_status="$(
    printf 'Authorization: Bearer %s\n' "$test_bearer" |
      curl -q -sS -H @- -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:39777/public-files/api/file?path=$blocked_file"
  )"
  [[ "$blocked_status" == 404 ]] ||
    fail "nested or covered file $blocked_file returned $blocked_status"
done

for management_path in /v1 /v2 /v3 /debug /swagger /public-files/../v1; do
  status="$(
    curl -q -sS --path-as-is -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:39777${management_path}"
  )"
  [[ "$status" == 404 ]] ||
    fail "management path ${management_path} returned ${status}, want 404"
done
wait_until "unchanged management sentinel" sentinel_is_unchanged

activate_public_binary \
  "$systemd_test_binary" \
  "systemd coordinator cleanup binary activation"
coordinator_cleanup_deadline=$((SECONDS + 15))
wait_until_before "storage workers before coordinator SIGKILL load" \
  "$coordinator_cleanup_deadline" \
  storage_worker_count_is 0
start_slow_download
wait_until_before "slow download before coordinator SIGKILL response" \
  "$coordinator_cleanup_deadline" \
  slow_download_is_ready \
  "$latest_slow_download_pid" \
  "$latest_slow_download_ready_file" \
  "$latest_slow_download_failure_file" \
  "$latest_slow_download_start_time"
wait_until_before "active worker before coordinator SIGKILL" \
  "$coordinator_cleanup_deadline" \
  storage_worker_count_is 1
wait_until_before "stopped storage worker before coordinator SIGKILL" \
  "$coordinator_cleanup_deadline" \
  storage_workers_are_stopped 1
worker_before_coordinator_kill="$(storage_worker_pids)"
[[ "$worker_before_coordinator_kill" =~ ^[0-9]+$ ]] ||
  fail "could not capture the worker before coordinator SIGKILL"
worker_before_coordinator_kill_start_time="$(
  process_start_time "$worker_before_coordinator_kill"
)" || fail "could not capture the coordinator-cleanup worker identity"
sudo systemctl kill \
  "$systemctl_kill_selector" \
  --signal=SIGKILL \
  "$service_unit"
wait_until_before "public service restart after SIGKILL" \
  "$coordinator_cleanup_deadline" \
  service_has_new_pid
wait_until_before "old worker cgroup cleanup after coordinator SIGKILL" \
  "$coordinator_cleanup_deadline" \
  process_identity_is_gone \
  "$worker_before_coordinator_kill" \
  "$worker_before_coordinator_kill_start_time"
cleanup_background_downloads
wait_until "public portal after SIGKILL" page_is_ready
wait_until "unchanged management sentinel after SIGKILL" sentinel_is_unchanged
portal_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"
portal_invocation="$(
  sudo systemctl show --property=InvocationID --value "$service_unit"
)"
assert_service_cgroup_limits
assert_systemd_credential_for_pid "$portal_pid"
assert_service_api_vfs_isolation "$portal_pid"

activate_public_binary \
  "$production_binary" \
  "production binary restoration after coordinator cleanup"
printf 'invalid verifier\n' | sudo tee "$verifier" >/dev/null
sudo chmod 0600 "$verifier"
sudo systemctl restart "$service_unit" >/dev/null 2>&1 || true
wait_until "fail-closed invalid verifier state" service_is_failed
failed_portal_pid="$(
  sudo systemctl show --property=MainPID --value "$service_unit"
)"
[[ "$failed_portal_pid" == 0 ]] ||
  fail "failed verifier left a service process running: $failed_portal_pid"
wait_until "unchanged management sentinel after invalid verifier" \
  sentinel_is_unchanged

sudo install -o root -g root -m 0600 "$good_verifier" "$verifier"
sudo systemctl reset-failed "$service_unit"
# A socket whose trigger repeatedly failed may itself enter trigger-limit-hit.
# Reset it only after the verifier has been restored, then require a clean
# positive activation instead of ignoring either unit's recovery result.
if sudo systemctl is-failed --quiet "$socket_unit"; then
  sudo systemctl reset-failed "$socket_unit"
fi
if ! sudo systemctl is-active --quiet "$socket_unit"; then
  sudo systemctl start "$socket_unit"
fi
wait_until "public portal recovery after verifier restore" page_is_ready
wait_until "unchanged management sentinel after recovery" sentinel_is_unchanged
sudo systemctl is-active --quiet "$socket_unit"
sudo systemctl is-active --quiet "$service_unit"
portal_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"
assert_service_cgroup_limits
assert_systemd_credential_for_pid "$portal_pid"
assert_service_api_vfs_isolation "$portal_pid"

printf '%s\n' \
  'public-files systemd integration passed: isolated identity, root, network,' \
  'socket activation, credential loading, crash recovery, and daemon independence'
