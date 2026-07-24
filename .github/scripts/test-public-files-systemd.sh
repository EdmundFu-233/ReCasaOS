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
test_bearer='rc1_AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'

case "$workspace" in
  /run/recasaos-public-files-ci-[0-9]*-[0-9]*) ;;
  *) fail "refusing unsafe workspace path: $workspace" ;;
esac

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
for required_tool in mount mountpoint umount; do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "required mount test tool is unavailable: $required_tool"
done
account_cleanup_authorized=1
nested_mount_cleanup_required=0

cleanup_problem() {
  printf 'public-files systemd test cleanup: %s\n' "$*" >&2
  cleanup_failed=1
}

cleanup_stop_unit() {
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
      "could not query $unit before stopping it (status $command_status)"
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
      "could not query $unit state before stopping it (status $command_status)"
    return
  fi
  if [[ -z "$active_state" ]]; then
    cleanup_problem "systemd returned an empty ActiveState for $unit"
    return
  fi
  if [[ "$load_state" == not-found && "$active_state" == inactive ]]; then
    return
  fi
  if [[ "$active_state" == inactive || "$active_state" == failed ]]; then
    return
  fi

  sudo systemctl stop "$unit" >/dev/null
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem "could not stop $unit (status $command_status)"
  fi

  active_state="$(
    sudo systemctl show --property=ActiveState --value "$unit"
  )"
  command_status=$?
  if [[ "$command_status" != 0 ]]; then
    cleanup_problem \
      "could not verify $unit after stopping it (status $command_status)"
    return
  fi
  if [[ "$active_state" != inactive && "$active_state" != failed ]]; then
    cleanup_problem \
      "$unit remains in ActiveState=${active_state:-unknown} after stop"
  fi
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

cleanup() {
  status=$?
  cleanup_failed=0
  workspace_removal_safe=1
  trap - EXIT
  set +e

  for unit in "$socket_unit" "$service_unit" "$sentinel_unit"; do
    cleanup_stop_unit "$unit"
  done

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
printf 'must remain covered by the nested mount\n' |
  sudo tee "$nested_mount/must-remain-covered.txt" >/dev/null
printf 'nested mount content must be rejected\n' |
  sudo tee "$nested_backing/nested-mount.txt" >/dev/null
sudo chown root:recasaos-public \
  "$share/report.txt" \
  "$nested_mount/must-remain-covered.txt" \
  "$nested_backing/nested-mount.txt"
sudo chmod 0640 \
  "$share/report.txt" \
  "$nested_mount/must-remain-covered.txt" \
  "$nested_backing/nested-mount.txt"
nested_mount_cleanup_required=1
sudo mount --bind "$nested_backing" "$nested_mount"
sudo chmod 0555 "$rootfs/proc" "$rootfs/sys"
sudo chmod 01777 "$rootfs/tmp" "$rootfs/var/tmp"

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
  'ConditionPathIsRegular=' \
  "ConditionPathIsDirectory=$share" \
  "ConditionPathIsRegular=$verifier" \
  'StartLimitIntervalSec=15s' \
  'StartLimitBurst=3' \
  '' \
  '[Service]' \
  "RootDirectory=$rootfs" \
  'BindReadOnlyPaths=' \
  "BindReadOnlyPaths=$share:/srv/public:rbind" \
  'LoadCredential=' \
  "LoadCredential=recasaos-public-file-verifier:$verifier" \
  'RestartSec=1s' |
  sudo tee "$override_path" >/dev/null
sudo chmod 0644 "$override_path"
sudo install -d -o root -g root -m 0755 "$socket_override_dir"
printf '%s\n' \
  '[Unit]' \
  'ConditionPathIsDirectory=' \
  'ConditionPathIsRegular=' \
  "ConditionPathIsDirectory=$share" \
  "ConditionPathIsRegular=$verifier" |
  sudo tee "$socket_override_path" >/dev/null
sudo chmod 0644 "$socket_override_path"

sudo systemctl daemon-reload
sudo systemd-analyze verify "$socket_unit" "$service_unit"
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

root_net_ns="$(stat -Lc %i /proc/1/ns/net)"
portal_net_ns="$(sudo stat -Lc %i "/proc/$portal_pid/ns/net")"
root_mount_ns="$(stat -Lc %i /proc/1/ns/mnt)"
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
sudo test ! -e "/proc/$portal_pid/root/sys/kernel" ||
  fail "host sysfs is visible in the service root"
sudo test ! -e "/proc/$portal_pid/root/proc/sys" ||
  fail "non-process procfs APIs are visible in the service root"
sudo test ! -e "/proc/$portal_pid/root/dev/shm" ||
  fail "shared-memory device path is visible in the service root"
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

credential_path="/proc/$portal_pid/root/run/credentials/$service_unit/recasaos-public-file-verifier"
sudo test -r "$credential_path" ||
  fail "systemd credential is unavailable in the service root"
credential_metadata="$(sudo stat -c '%u:%g:%a' "$credential_path")"
IFS=: read -r credential_uid credential_gid credential_mode \
  <<<"$credential_metadata"
[[ "$credential_uid" == "$service_uid" ]] ||
  fail "systemd credential owner is unsafe: $credential_metadata"
[[ "$credential_mode" == 400 || "$credential_mode" == 600 ]] ||
  fail "systemd credential mode is unsafe: $credential_metadata"

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
cmp "$share/report.txt" "$response_file" ||
  fail "downloaded bytes differ from the approved file"

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

sudo kill -KILL "$portal_pid"
wait_until "public service restart after SIGKILL" service_has_new_pid
wait_until "public portal after SIGKILL" page_is_ready
wait_until "unchanged management sentinel after SIGKILL" sentinel_is_unchanged
portal_pid="$(sudo systemctl show --property=MainPID --value "$service_unit")"

printf 'invalid verifier\n' | sudo tee "$verifier" >/dev/null
sudo chmod 0600 "$verifier"
sudo systemctl restart "$service_unit" >/dev/null 2>&1 || true
wait_until "fail-closed invalid verifier state" service_is_failed
wait_until "unchanged management sentinel after invalid verifier" \
  sentinel_is_unchanged

sudo install -o root -g root -m 0600 "$good_verifier" "$verifier"
sudo systemctl reset-failed "$service_unit"
wait_until "public portal recovery after verifier restore" page_is_ready
wait_until "unchanged management sentinel after recovery" sentinel_is_unchanged

printf '%s\n' \
  'public-files systemd integration passed: isolated identity, root, network,' \
  'socket activation, credential loading, crash recovery, and daemon independence'
