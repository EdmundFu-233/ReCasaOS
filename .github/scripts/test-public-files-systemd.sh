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
management_dir="${workspace}/management"
response_file="${workspace}/response"
nested_backing="${workspace}/nested-backing"
nested_mount="${share}/covered"
host_shm_sentinel_prefix="/dev/shm/recasaos-public-files-ci-${run_key}."
host_shm_sentinel=
test_bearer='rc1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
# Exceed the service's 512 MiB total memory ceiling so a completed worker
# cannot be mistaken for a connection that is still under peer backpressure.
# truncate creates a hole; the fixture consumes no GiB of runner storage.
worker_load_bytes=1073741824

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
  find getfacl mktemp mount mountpoint pgrep ps ss truncate umount
do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "required mount test tool is unavailable: $required_tool"
done
[[ -x /usr/bin/python3 ]] ||
  fail "required Python interpreter is unavailable: /usr/bin/python3"
account_cleanup_authorized=1
nested_mount_cleanup_required=0
host_shm_sentinel_created=0
slow_download_pids=()
slow_download_ready_files=()
slow_download_failure_files=()
slow_download_sequence=0
latest_slow_download_pid=
latest_slow_download_ready_file=
latest_slow_download_failure_file=
last_storage_worker_count=0
max_storage_worker_count=0

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

cleanup_background_downloads() {
  local pid
  for pid in "${slow_download_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${slow_download_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  slow_download_pids=()
  slow_download_ready_files=()
  slow_download_failure_files=()
  latest_slow_download_pid=
  latest_slow_download_ready_file=
  latest_slow_download_failure_file=
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

wait_until() {
  description=$1
  shift
  for ((attempt = 0; attempt < 150; attempt++)); do
    if "$@"; then
      return 0
    fi
    sleep 0.1
  done
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

service_is_failed() {
  sudo systemctl is-failed --quiet "$service_unit"
}

service_has_new_pid() {
  current_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"
  [[ "$current_pid" =~ ^[0-9]+$ && "$current_pid" -gt 1 &&
    "$current_pid" != "$portal_pid" ]]
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
  local process_state
  local pid=$1

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 ]] || return 1
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

print_storage_worker_diagnostics() {
  local client_index
  local client_pid
  local failure_file
  local ready_file
  printf 'storage worker diagnostics: last=%s max=%s pids=%q\n' \
    "$last_storage_worker_count" \
    "$max_storage_worker_count" \
    "$(storage_worker_pids)" >&2
  sudo ps -o pid=,ppid=,stat=,etime=,args= --ppid "$portal_pid" >&2 || true
  for client_index in "${!slow_download_pids[@]}"; do
    client_pid="${slow_download_pids[$client_index]}"
    ready_file="${slow_download_ready_files[$client_index]}"
    failure_file="${slow_download_failure_files[$client_index]}"
    if slow_download_process_is_live "$client_pid"; then
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
    "$service_unit" >&2 || true
  sudo ss -H -tinp \
    '( sport = :39777 or dport = :39777 )' >&2 || true
  sudo journalctl --no-pager --output=short-monotonic --lines=80 \
    --unit="$socket_unit" --unit="$service_unit" >&2 || true
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

  if [[ -s "$failure_file" ]]; then
    while IFS= read -r failure_line; do
      printf 'slow download client %s error: %s\n' \
        "$pid" "$failure_line" >&2
    done <"$failure_file"
    fail "slow download client $pid failed before becoming ready"
  fi
  if [[ -e "$ready_file" || -L "$ready_file" ]]; then
    [[ -f "$ready_file" && ! -L "$ready_file" ]] ||
      fail "slow download client $pid produced an unsafe ready marker"
    slow_download_marker_is_valid "$ready_file" ||
      fail "slow download client $pid produced an invalid ready marker"
    slow_download_process_is_live "$pid" ||
      fail "slow download client $pid exited after becoming ready"
    return 0
  fi
  slow_download_process_is_live "$pid" ||
    fail "slow download client $pid exited before becoming ready"
  return 1
}

slow_downloads_are_healthy() {
  local client_index

  for client_index in "${!slow_download_pids[@]}"; do
    slow_download_is_ready \
      "${slow_download_pids[$client_index]}" \
      "${slow_download_ready_files[$client_index]}" \
      "${slow_download_failure_files[$client_index]}" || return 1
  done
}

start_slow_download() {
  local failure_file
  local pid
  local ready_file
  local ready_temp_file

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
    client.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    if client.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF) > 16384:
        raise RuntimeError("kernel did not preserve the bounded receive buffer")
    if not hasattr(socket, "TCP_WINDOW_CLAMP"):
        raise RuntimeError("kernel TCP window clamp support is unavailable")
    client.setsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP, 4096)
    if client.getsockopt(socket.IPPROTO_TCP, socket.TCP_WINDOW_CLAMP) > 16384:
        raise RuntimeError("kernel did not preserve the bounded TCP window")
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
            raise RuntimeError("server closed before sending response headers")
        response.extend(chunk)
        if len(response) > 32768:
            raise RuntimeError("response headers exceeded the bounded limit")
    header_block = bytes(response).split(b"\r\n\r\n", 1)[0]
    header_lines = header_block.split(b"\r\n")
    status_line = header_lines[0].split(b" ", 2)
    if len(status_line) < 2 or status_line[1] != b"200":
        raise RuntimeError("slow download did not receive HTTP 200")
    content_lengths = []
    for header_line in header_lines[1:]:
        if b":" not in header_line:
            raise RuntimeError("slow download received a malformed header")
        header_name, header_value = header_line.split(b":", 1)
        if header_name.lower() == b"content-length":
            content_lengths.append(header_value.strip())
    expected_length = sys.argv[2].encode("ascii")
    if expected_length != b"1073741824":
        raise RuntimeError("slow download fixture length is invalid")
    if content_lengths != [expected_length]:
        raise RuntimeError("slow download received an unexpected content length")

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
  slow_download_pids+=("$pid")
  slow_download_ready_files+=("$ready_file")
  slow_download_failure_files+=("$failure_file")
  latest_slow_download_pid=$pid
  latest_slow_download_ready_file=$ready_file
  latest_slow_download_failure_file=$failure_file
}

process_is_gone() {
  [[ ! -e "/proc/$1" ]]
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
  -o "$workspace/recasaos-public-files" \
  ./cmd/recasaos-public-files
file "$workspace/recasaos-public-files" | grep -q 'statically linked' ||
  fail "public-files binary is not static"
sudo install -o root -g root -m 0755 \
  "$workspace/recasaos-public-files" \
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
  "$workspace/recasaos-public-files" \
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

wait_until "storage workers before bounded load" storage_worker_count_is 0
for expected_worker_count in {1..8}; do
  start_slow_download
  wait_until "slow download $expected_worker_count response" \
    slow_download_is_ready \
    "$latest_slow_download_pid" \
    "$latest_slow_download_ready_file" \
    "$latest_slow_download_failure_file"
  wait_until "$expected_worker_count bounded storage workers" \
    storage_worker_count_is "$expected_worker_count"
done

ninth_status="$(
  printf 'Authorization: Bearer %s\n' "$test_bearer" |
    curl -q -sS --max-time 5 -H @- -o /dev/null -w '%{http_code}' \
      'http://127.0.0.1:39777/public-files/api/file?path=worker-load.bin'
)"
[[ "$ninth_status" == 503 ]] ||
  fail "ninth concurrent storage request returned $ninth_status, want 503"

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

cleanup_background_downloads
wait_until "storage worker reap after bounded load" storage_worker_count_is 0

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

wait_until "storage workers before coordinator SIGKILL load" \
  storage_worker_count_is 0
start_slow_download
wait_until "slow download before coordinator SIGKILL response" \
  slow_download_is_ready \
  "$latest_slow_download_pid" \
  "$latest_slow_download_ready_file" \
  "$latest_slow_download_failure_file"
wait_until "active worker before coordinator SIGKILL" storage_worker_count_is 1
worker_before_coordinator_kill="$(storage_worker_pids)"
[[ "$worker_before_coordinator_kill" =~ ^[0-9]+$ ]] ||
  fail "could not capture the worker before coordinator SIGKILL"
sudo kill -KILL "$portal_pid"
wait_until "public service restart after SIGKILL" service_has_new_pid
wait_until "old worker cgroup cleanup after coordinator SIGKILL" \
  process_is_gone "$worker_before_coordinator_kill"
cleanup_background_downloads
wait_until "public portal after SIGKILL" page_is_ready
wait_until "unchanged management sentinel after SIGKILL" sentinel_is_unchanged
portal_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"
assert_service_cgroup_limits
assert_systemd_credential_for_pid "$portal_pid"
assert_service_api_vfs_isolation "$portal_pid"

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
