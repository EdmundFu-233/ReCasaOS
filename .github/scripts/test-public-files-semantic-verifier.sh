#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files semantic verifier test failed: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
verifier="$repo_root/deploy/systemd/verify-public-files-units.sh"
service="$repo_root/build/sysroot/usr/lib/systemd/system/recasaos-public-files.service"
socket="$repo_root/build/sysroot/usr/lib/systemd/system/recasaos-public-files.socket"
work_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)"
work_prefix="$work_parent/recasaos-semantic-verifier."

safe_work_dir_name() {
  local candidate=$1
  local suffix
  case "$candidate" in
    "$work_prefix"*) suffix=${candidate#"$work_prefix"} ;;
    *) return 1 ;;
  esac
  [[ "$suffix" =~ ^[A-Za-z0-9]{6}$ ]]
}

work_dir="$(mktemp -d "$work_parent/recasaos-semantic-verifier.XXXXXX")"
safe_work_dir_name "$work_dir" ||
  fail "mktemp returned an unsafe directory: $work_dir"
[[ -d "$work_dir" && ! -L "$work_dir" ]] ||
  fail "mktemp did not create a safe directory: $work_dir"

cleanup_work_dir() {
  if [[ -n "${work_dir:-}" ]] && safe_work_dir_name "$work_dir"; then
    if [[ -d "$work_dir" && ! -L "$work_dir" ]]; then
      rm -rf -- "$work_dir"
    elif [[ -e "$work_dir" || -L "$work_dir" ]]; then
      printf '%s\n' \
        "public-files semantic verifier test retained unsafe cleanup target: $work_dir" \
        >&2
    fi
    work_dir=
  fi
}
trap cleanup_work_dir EXIT

fixture="$work_dir/fixture"
fake_bin="$work_dir/bin"
install -d "$fixture" "$fake_bin"
binary="$fixture/recasaos-public-files"
service_drop_in="$fixture/service.conf"
socket_drop_in="$fixture/socket.conf"
install -m 0755 /bin/sh "$binary"
printf '%s\n' '[Unit]' 'ConditionPathIsDirectory=/tmp' >"$service_drop_in"
printf '%s\n' '[Unit]' 'ConditionPathIsDirectory=/tmp' >"$socket_drop_in"

fake_analyze="$fake_bin/systemd-analyze"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  '[[ "$#" == 3 && "$1" == verify ]]' \
  'socket=$2' \
  'service=$3' \
  '[[ "$(basename -- "$socket")" == recasaos-public-files.socket ]]' \
  '[[ "$(basename -- "$service")" == recasaos-public-files.service ]]' \
  '[[ -x "$(dirname -- "$service")/recasaos-public-files" ]]' \
  '! grep -q "^ExecStart=/usr/bin/recasaos-public-files " "$service"' \
  '[[ "$(grep -c "^ExecStart=" "$service")" == 1 ]]' \
  'grep -Eq '"'"'^ExecStart=/tmp/recasaos-systemd-verify\.[^/]+/recasaos-public-files serve --activation-name=public-files --listen=127\.0\.0\.1:39777 --root=/srv/public --verifier-file=\$\{CREDENTIALS_DIRECTORY\}/recasaos-public-file-verifier$'"'"' "$service"' \
  '[[ "$(grep -Fxc "Type=notify" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "NotifyAccess=main" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/cgroup.controllers" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/system.slice/memory.max" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/system.slice/memory.swap.max" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/system.slice/pids.max" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/cgroup.controllers" "$socket")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/system.slice/memory.max" "$socket")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/system.slice/memory.swap.max" "$socket")" == 1 ]]' \
  '[[ "$(grep -Fxc "ConditionPathExists=/sys/fs/cgroup/system.slice/pids.max" "$socket")" == 1 ]]' \
  '[[ "$(grep -Fxc "BindReadOnlyPaths=/srv/recasaos-public:/srv/public:rbind" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.max:/run/recasaos-cgroup/memory.max:norbind" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.swap.max:/run/recasaos-cgroup/memory.swap.max:norbind" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/pids.max:/run/recasaos-cgroup/pids.max:norbind" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "LimitNOFILE=512" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "TasksMax=256" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "MemoryMax=512M" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "MemorySwapMax=0" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "KillMode=control-group" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "TimeoutStartSec=30s" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "SystemCallFilter=@system-service" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "SystemCallFilter=~@clock @cpu-emulation @debug @keyring @module @mount @obsolete @privileged @raw-io @reboot @swap clone3 memfd_create" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "InaccessiblePaths=+/sys -+/dev/shm" "$service")" == 1 ]]' \
  '[[ "$(grep -Fxc "ReadOnlyPaths=+/tmp +/var/tmp" "$service")" == 1 ]]' \
  '! grep -q "^TemporaryFileSystem=" "$service"' \
  '[[ -f "${service}.d/ci.conf" ]]' \
  '[[ -f "${socket}.d/ci.conf" ]]' \
  'case "${FAKE_SYSTEMD_ANALYZE_MODE:-success}" in' \
  '  success) exit 0 ;;' \
  '  warning) printf "%s\n" "synthetic warning" >&2; exit 0 ;;' \
  '  failure) printf "%s\n" "synthetic failure" >&2; exit 1 ;;' \
  '  *) exit 2 ;;' \
  'esac' >"$fake_analyze"
chmod 0755 "$fake_analyze"

PATH="$fake_bin:$PATH" \
  "$verifier" \
  "$service" "$socket" "$binary" "$service_drop_in" "$socket_drop_in" \
  >/dev/null

if FAKE_SYSTEMD_ANALYZE_MODE=warning PATH="$fake_bin:$PATH" \
  "$verifier" \
  "$service" "$socket" "$binary" "$service_drop_in" "$socket_drop_in" \
  >/dev/null 2>&1; then
  fail "semantic verifier accepted analyzer warnings"
fi

if FAKE_SYSTEMD_ANALYZE_MODE=failure PATH="$fake_bin:$PATH" \
  "$verifier" \
  "$service" "$socket" "$binary" "$service_drop_in" "$socket_drop_in" \
  >/dev/null 2>&1; then
  fail "semantic verifier accepted analyzer failure"
fi

duplicate_service="$fixture/duplicate.service"
install -m 0644 "$service" "$duplicate_service"
printf '%s\n' \
  'ExecStart=/usr/bin/recasaos-public-files duplicate' \
  >>"$duplicate_service"
if PATH="$fake_bin:$PATH" \
  "$verifier" "$duplicate_service" "$socket" "$binary" \
  >/dev/null 2>&1; then
  fail "semantic verifier accepted duplicate ExecStart prefixes"
fi

linked_binary="$fixture/linked-binary"
ln -s -- "$binary" "$linked_binary"
if PATH="$fake_bin:$PATH" \
  "$verifier" "$service" "$socket" "$linked_binary" \
  >/dev/null 2>&1; then
  fail "semantic verifier accepted a symlink binary"
fi

malicious_bin="$work_dir/malicious-bin"
install -d "$malicious_bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "%s\n" "/tmp/recasaos-systemd-verify.abcdef/../../unsafe"' \
  >"$malicious_bin/mktemp"
chmod 0755 "$malicious_bin/mktemp"
if PATH="$malicious_bin:$fake_bin:$PATH" \
  "$verifier" "$service" "$socket" "$binary" \
  >/dev/null 2>&1; then
  fail "semantic verifier accepted an unsafe mktemp path"
fi

printf '%s\n' 'public-files semantic verifier tests: passed'
