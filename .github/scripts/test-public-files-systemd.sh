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
[[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted ]] ||
  fail "GitHub did not identify this as a hosted runner"
[[ -d /opt/hostedtoolcache ]] ||
  fail "the GitHub-hosted runner marker is missing"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ID is missing or unsafe"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ATTEMPT is missing or unsafe"
[[ "$(cat /proc/1/comm)" == systemd ]] ||
  fail "PID 1 is not systemd"
[[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]] ||
  fail "the runner is not using cgroup v2"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd -- "$repo_root"
run_key="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
workspace="/run/recasaos-public-files-ci-${run_key}"
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
nested_backing="${workspace}/nested-backing"
nested_mount="${share}/covered"
host_shm_sentinel_prefix="/dev/shm/recasaos-public-files-ci-${run_key}."
host_shm_sentinel=
test_bearer='rc1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
# The fixture is sparse. The dedicated CI-tagged worker returns its first real
# chunk, then stops itself only for this exact file so the HTTP client can
# validate committed response headers before worker-capacity checks begin.
worker_load_bytes=67108864
storage_worker_address_space_ceiling=2147483648
storage_worker_address_space_minimum_reserve=134217728

case "$workspace" in
  /run/recasaos-public-files-ci-[0-9]*-[0-9]*) ;;
  *) fail "refusing unsafe workspace path: $workspace" ;;
esac
[[ "$host_shm_sentinel_prefix" =~ ^/dev/shm/recasaos-public-files-ci-[0-9]+-[0-9]+\.$ ]] ||
  fail "refusing unsafe shared-memory sentinel prefix: $host_shm_sentinel_prefix"

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
  cmp find getfacl mktemp mount mountpoint pgrep ps sort ss systemctl truncate umount
do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "required mount test tool is unavailable: $required_tool"
done
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
limit_end = "\nPYTHON\n}\n\nprint_capacity_journal_diagnostics()"
if script.count(limit_start) != 1 or script.count(limit_end) != 1:
    raise SystemExit("address-space evidence sentinels are not unique")
limit_source = script.split(limit_start, 1)[1].split(limit_end, 1)[0]
compile(
    limit_source,
    "assert_storage_worker_address_space_limit.py",
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

terminate_exact_background_process() {
  local pid=$1
  local start_time=$2

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 &&
    "$start_time" =~ ^[0-9]+$ ]] || return 1
  /usr/bin/python3 -c '
import os
import signal
import sys

pid = int(sys.argv[1])
expected_start = sys.argv[2].encode("ascii")
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
        signal.pidfd_send_signal(pidfd, signal.SIGTERM, None, 0)
    except ProcessLookupError:
        pass
finally:
    os.close(pidfd)
' "$pid" "$start_time"
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
    sudo mountpoint -q -- "$nested_mount" >/dev/null 2>&1
    mountpoint_status=$?
    case "$mountpoint_status" in
      0)
        sudo umount -- "$nested_mount"
        command_status=$?
        if [[ "$command_status" != 0 ]]; then
          cleanup_problem \
            "could not unmount $nested_mount (status $command_status)"
          workspace_removal_safe=0
        else
          sudo mountpoint -q -- "$nested_mount" >/dev/null 2>&1
          mountpoint_status=$?
          case "$mountpoint_status" in
            0)
              cleanup_problem "nested mount remains active: $nested_mount"
              workspace_removal_safe=0
              ;;
            32)
              ;;
            *)
              cleanup_problem \
                "could not verify nested mount removal (status $mountpoint_status)"
              workspace_removal_safe=0
              ;;
          esac
        fi
        ;;
      32)
        ;;
      *)
        cleanup_problem \
          "could not determine nested mount state (status $mountpoint_status)"
        workspace_removal_safe=0
        ;;
    esac
  fi

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
          allowed["recasaos-systemd-test-event=coordinator-read-response"] = 1
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

  [[ "$capacity_events" =~ ^/run/recasaos-public-files-ci-[0-9]+-[0-9]+/capacity-events$ ]] ||
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
      # Eight successful holders emit seven events each. The ninth request
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
      expected["recasaos-systemd-test-event=coordinator-read-response"] = 8
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
  [[ "$ready_file" =~ ^/run/recasaos-public-files-ci-[0-9]+-[0-9]+/slow-download-[0-9]+\.ready$ ]] ||
    fail "refusing unsafe slow download ready path: $ready_file"
  [[ "$failure_file" =~ ^/run/recasaos-public-files-ci-[0-9]+-[0-9]+/slow-download-[0-9]+\.failure$ ]] ||
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

runner_uid="$(id -u)"
runner_gid="$(id -g)"
sudo install -d -o "$runner_uid" -g "$runner_gid" -m 0755 "$workspace"
sudo install -d -o root -g root -m 0755 \
  "$rootfs" "$rootfs/usr" "$rootfs/usr/bin" "$rootfs/srv" \
  "$rootfs/proc" "$rootfs/sys" "$rootfs/dev" "$rootfs/run" \
  "$rootfs/tmp" "$rootfs/var" "$rootfs/var/tmp"
sudo install -d -o root -g root -m 0555 \
  "$rootfs/run/recasaos-cgroup"
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
  "$share" "$nested_backing" "$nested_mount" "$rootfs/srv/public"
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
      !(
        $1 == "github.com/IceWhaleTech/CasaOS/pkg/publicfiles" &&
        $2 == "GoFiles" &&
        $3 ~ /^worker_systemd_test_gate_(disabled|enabled)_linux\.go$/
      )
    '
)"
systemd_test_shared_build_inputs="$(
  printf '%s\n' "$systemd_test_build_inputs" |
    awk '
      !(
        $1 == "github.com/IceWhaleTech/CasaOS/pkg/publicfiles" &&
        $2 == "GoFiles" &&
        $3 ~ /^worker_systemd_test_gate_(disabled|enabled)_linux\.go$/
      )
    '
)"
[[ -n "$production_shared_build_inputs" &&
  "$production_shared_build_inputs" == "$systemd_test_shared_build_inputs" ]] ||
  fail "production and tagged binaries select different shared build inputs"
for built_binary in "$production_binary" "$systemd_test_binary"; do
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
sudo test ! -e "/proc/$portal_pid/root/run/recasaos-public-files-ci-$run_key" ||
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
worker_capacity_deadline=$((SECONDS + 15))
for expected_worker_count in {1..8}; do
  start_slow_download
  wait_until_before "slow download $expected_worker_count response" \
    "$worker_capacity_deadline" \
    slow_download_is_ready \
    "$latest_slow_download_pid" \
    "$latest_slow_download_ready_file" \
    "$latest_slow_download_failure_file" \
    "$latest_slow_download_start_time"
  wait_until_before "$expected_worker_count bounded storage workers" \
    "$worker_capacity_deadline" \
    storage_worker_count_is "$expected_worker_count"
  wait_until_before "$expected_worker_count stopped storage workers" \
    "$worker_capacity_deadline" \
    storage_workers_are_stopped "$expected_worker_count"
done
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
wait_until_before "storage worker capacity event chain" \
  "$worker_capacity_deadline" \
  capacity_phase_events_are_complete
for bounded_worker_index in "${!bounded_worker_pids[@]}"; do
  assert_storage_worker_address_space_limit \
    "${bounded_worker_pids[$bounded_worker_index]}" \
    "${bounded_worker_start_times[$bounded_worker_index]}" \
    systemd-test
done

tasks_current="$(
  sudo systemctl show --property=TasksCurrent --value "$service_unit"
)"
memory_current="$(
  sudo systemctl show --property=MemoryCurrent --value "$service_unit"
)"
memory_peak="$(
  sudo systemctl show --property=MemoryPeak --value "$service_unit"
)"
[[ "$tasks_current" =~ ^[0-9]+$ && "$tasks_current" -le 224 ]] ||
  fail "eight-worker TasksCurrent=$tasks_current leaves insufficient headroom"
[[ "$memory_current" =~ ^[0-9]+$ && "$memory_current" -le 469762048 ]] ||
  fail "eight-worker MemoryCurrent=$memory_current leaves insufficient headroom"
[[ "$memory_peak" =~ ^[0-9]+$ && "$memory_peak" -le 469762048 ]] ||
  fail "eight-worker MemoryPeak=$memory_peak leaves insufficient headroom"

listener_inode="$(
  sudo awk \
    '$2 == "0100007F:9B61" && $4 == "0A" { print $10; exit }' \
    /proc/net/tcp
)"
[[ "$listener_inode" =~ ^[0-9]+$ ]] ||
  fail "could not resolve the public listener inode"
while IFS= read -r worker_pid; do
  [[ "$worker_pid" =~ ^[0-9]+$ && "$worker_pid" -gt 1 ]] ||
    fail "invalid storage worker PID: $worker_pid"
  worker_command="$(
    sudo cat "/proc/$worker_pid/cmdline" | tr '\0' ' '
  )"
  [[ "$worker_command" == *"--internal-public-files-storage-worker file"* ]] ||
    fail "unexpected storage worker command line"
  if printf '%s' "$worker_command" | grep -Fq "$test_bearer"; then
    fail "raw bearer is present in a storage worker command line"
  fi
  if sudo cat "/proc/$worker_pid/environ" |
    tr '\0' '\n' |
    grep -F -- "$test_bearer" >/dev/null; then
    fail "raw bearer is present in a storage worker environment"
  fi
  [[ "$(sudo stat -Lc %u "/proc/$worker_pid/mem")" == 0 ]] ||
    fail "storage worker process memory remains dumpable"
  while IFS= read -r descriptor_path; do
    descriptor="${descriptor_path##*/}"
    [[ "$descriptor" =~ ^[0-9]+$ ]] ||
      fail "storage worker exposed a nonnumeric descriptor"
    descriptor_target="$(sudo readlink "$descriptor_path")"
    [[ "$descriptor_target" != "socket:[$listener_inode]" ]] ||
      fail "storage worker inherited the AF_INET listener"
    if [[ "$descriptor" -gt 2 ]]; then
      descriptor_flags="$(
        sudo awk '$1 == "flags:" { print $2; exit }' \
          "/proc/$worker_pid/fdinfo/$descriptor"
      )"
      [[ "$descriptor_flags" =~ ^[0-7]+$ ]] ||
        fail "storage worker descriptor $descriptor has invalid flags"
      descriptor_flags_value=$((8#$descriptor_flags))
      (( (descriptor_flags_value & 02000000) != 0 )) ||
        fail "storage worker descriptor $descriptor is not close-on-exec"
    fi
  done < <(
    sudo find "/proc/$worker_pid/fd" -mindepth 1 -maxdepth 1 -print
  )
done < <(storage_worker_pids)
((SECONDS < worker_capacity_deadline + 10)) ||
  fail "bounded worker phase exceeded its 25-second cancellation budget"
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
