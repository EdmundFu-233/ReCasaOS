#!/bin/sh
set -eu

repo_root=${1:-.}
unit_dir="${repo_root}/build/sysroot/usr/lib/systemd/system"
service="${unit_dir}/recasaos-public-files.service"
socket="${unit_dir}/recasaos-public-files.socket"
sysusers="${repo_root}/build/sysroot/usr/lib/sysusers.d/recasaos-public-files.conf"
tmpfiles="${repo_root}/build/sysroot/usr/lib/tmpfiles.d/recasaos-public-files.conf"
retired="${repo_root}/deploy/systemd/recasaos-public-files-verifier.conf.example"
semantic_verifier="${repo_root}/deploy/systemd/verify-public-files-units.sh"

fail() {
  printf '%s\n' "public-files unit check: $*" >&2
  exit 1
}

reject_line_continuations() {
  file=$1
  if LC_ALL=C grep -n '\\[[:space:]]*$' "$file" >/dev/null 2>&1; then
    fail "line continuations are forbidden in reviewed configuration: $file"
  fi
}

active_lines() {
  awk '
    /^[[:space:]]*($|#)/ { next }
    { print }
  ' "$1"
}

sectioned_active_lines() {
  awk '
    /^[[:space:]]*($|#)/ { next }
    {
      if ($0 ~ /^\[[^]]+\]$/) {
        section = $0
        print "@|" $0
        next
      }
      print section "|" $0
    }
  ' "$1"
}

key_assignments() {
  key=$1
  file=$2
  awk -v wanted_key="$key" '
    function trim(value) {
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
      return value
    }
    /^[[:space:]]*($|#)/ { next }
    {
      line = trim($0)
      if (line ~ /^\[[^]]+\]$/) {
        section = line
        next
      }
      equals = index(line, "=")
      if (equals == 0)
        next
      name = trim(substr(line, 1, equals - 1))
      if (name == wanted_key)
        print section "|" line
    }
  ' "$file"
}

require_exact_key_assignments() {
  section=$1
  key=$2
  file=$3
  shift 3
  assignments=$(key_assignments "$key" "$file")
  actual_count=$(
    printf '%s\n' "$assignments" |
      awk 'NF { count++ } END { print count + 0 }'
  )
  test "$actual_count" -eq "$#" ||
    fail "$key must have exactly $# reviewed assignment(s) in $file"

  for expected in "$@"; do
    reviewed="[${section}]|${expected}"
    match_count=$(
      printf '%s\n' "$assignments" |
        grep -F -x -c -- "$reviewed" || true
    )
    test "$match_count" -eq 1 ||
      fail "missing unique reviewed assignment '$expected' in [$section] of $file"
  done
}

require_exact_active_lines() {
  file=$1
  shift
  lines=$(active_lines "$file")
  actual_count=$(
    printf '%s\n' "$lines" |
      awk 'NF { count++ } END { print count + 0 }'
  )
  test "$actual_count" -eq "$#" ||
    fail "$file must contain exactly $# reviewed active line(s)"

  for expected in "$@"; do
    match_count=$(
      printf '%s\n' "$lines" |
        grep -F -x -c -- "$expected" || true
    )
    test "$match_count" -eq 1 ||
      fail "missing unique reviewed active line '$expected' in $file"
  done
}

require_exact_sectioned_active_lines() {
  file=$1
  shift
  actual=$(sectioned_active_lines "$file")
  reviewed_stream=
  section=
  for expected in "$@"; do
    case "$expected" in
      \[*\])
        section=$expected
        reviewed="@|${expected}"
        ;;
      *)
        test -n "$section" ||
          fail "reviewed line has no section in $file: $expected"
        reviewed="${section}|${expected}"
        ;;
    esac
    if test -z "$reviewed_stream"; then
      reviewed_stream=$reviewed
    else
      reviewed_stream="${reviewed_stream}
${reviewed}"
    fi
  done
  test "$actual" = "$reviewed_stream" ||
    fail "$file sectioned active lines differ in content or order"
}

reject_key_assignments() {
  key=$1
  file=$2
  assignments=$(key_assignments "$key" "$file")
  test -z "$assignments" ||
    fail "forbidden $key assignment in $file"
}

reject_active_pattern() {
  pattern=$1
  file=$2
  if grep -Ev '^[[:space:]]*(#|$)' "$file" |
    grep -E -- "$pattern" >/dev/null; then
    fail "forbidden pattern '$pattern' in $file"
  fi
}

for required in \
  "$service" "$socket" "$sysusers" "$tmpfiles" "$retired" "$semantic_verifier"
do
  test -f "$required" || fail "missing $required"
  test ! -L "$required" || fail "candidate payload is a symlink: $required"
done
test -x "$semantic_verifier" ||
  fail "semantic verifier is not executable: $semantic_verifier"
for reviewed_config in "$service" "$socket" "$sysusers" "$tmpfiles"; do
  reject_line_continuations "$reviewed_config"
done

require_exact_sectioned_active_lines "$service" \
  '[Unit]' \
  'Description=ReCasaOS isolated public-file portal' \
  'ConditionPathIsDirectory=/srv/recasaos-public' \
  'ConditionFileNotEmpty=/etc/recasaos/public-file.verifier' \
  'ConditionPathIsSymbolicLink=!/etc/recasaos/public-file.verifier' \
  'ConditionPathExists=/sys/fs/cgroup/cgroup.controllers' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.swap.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/pids.max' \
  'StartLimitIntervalSec=2min' \
  'StartLimitBurst=5' \
  '[Service]' \
  'Type=notify' \
  'NotifyAccess=main' \
  'User=recasaos-public' \
  'Group=recasaos-public' \
  'SupplementaryGroups=' \
  'UMask=0077' \
  'RootDirectory=/usr/lib/recasaos-public-files/rootfs' \
  'WorkingDirectory=/' \
  'MountAPIVFS=yes' \
  'BindReadOnlyPaths=/srv/recasaos-public:/srv/public:rbind' \
  'BindReadOnlyPaths=/run/systemd/notify:/run/systemd/notify:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.max:/run/recasaos-cgroup/memory.max:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.swap.max:/run/recasaos-cgroup/memory.swap.max:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/pids.max:/run/recasaos-cgroup/pids.max:norbind' \
  'LoadCredential=recasaos-public-file-verifier:/etc/recasaos/public-file.verifier' \
  'ExecStart=/usr/bin/recasaos-public-files serve --activation-name=public-files --listen=127.0.0.1:39777 --root=/srv/public --verifier-file=${CREDENTIALS_DIRECTORY}/recasaos-public-file-verifier' \
  'PrivateNetwork=yes' \
  'RestrictAddressFamilies=AF_UNIX' \
  'IPAddressDeny=any' \
  'IPAddressAllow=localhost' \
  'PrivateDevices=yes' \
  'PrivateMounts=yes' \
  'PrivateTmp=yes' \
  'ProtectProc=invisible' \
  'ProcSubset=pid' \
  'ProtectSystem=strict' \
  'ProtectHome=yes' \
  'ProtectHostname=yes' \
  'ProtectClock=yes' \
  'ProtectControlGroups=yes' \
  'ProtectKernelLogs=yes' \
  'ProtectKernelModules=yes' \
  'ProtectKernelTunables=yes' \
  'InaccessiblePaths=+/sys -+/dev/shm' \
  'ReadOnlyPaths=+/tmp +/var/tmp' \
  'CapabilityBoundingSet=' \
  'AmbientCapabilities=' \
  'NoNewPrivileges=yes' \
  'LockPersonality=yes' \
  'MemoryDenyWriteExecute=yes' \
  'RestrictNamespaces=yes' \
  'RestrictRealtime=yes' \
  'RemoveIPC=yes' \
  'SystemCallArchitectures=native' \
  'SystemCallFilter=@system-service' \
  'SystemCallFilter=~@clock @cpu-emulation @debug @keyring @module @mount @obsolete @privileged @raw-io @reboot @swap clone3 memfd_create' \
  'SystemCallErrorNumber=EPERM' \
  'LimitCORE=0' \
  'LimitNOFILE=512' \
  'TasksMax=256' \
  'MemoryMax=512M' \
  'MemorySwapMax=0' \
  'CPUQuota=100%' \
  'TimeoutStartSec=30s' \
  'TimeoutStopSec=10s' \
  'KillMode=control-group' \
  'Restart=on-failure' \
  'RestartSec=5s' \
  'StandardOutput=journal' \
  'StandardError=journal' \
  'SyslogIdentifier=recasaos-public-files'
require_exact_sectioned_active_lines "$socket" \
  '[Unit]' \
  'Description=ReCasaOS public-file portal socket' \
  'ConditionPathIsDirectory=/srv/recasaos-public' \
  'ConditionFileNotEmpty=/etc/recasaos/public-file.verifier' \
  'ConditionPathIsSymbolicLink=!/etc/recasaos/public-file.verifier' \
  'ConditionPathExists=/sys/fs/cgroup/cgroup.controllers' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/memory.swap.max' \
  'ConditionPathExists=/sys/fs/cgroup/system.slice/pids.max' \
  '[Socket]' \
  'ListenStream=127.0.0.1:39777' \
  'Accept=no' \
  'Service=recasaos-public-files.service' \
  'FileDescriptorName=public-files' \
  'Backlog=128' \
  'NoDelay=yes' \
  'IPAccounting=yes' \
  'IPAddressDeny=any' \
  'IPAddressAllow=localhost' \
  'TriggerLimitIntervalSec=30s' \
  'TriggerLimitBurst=3' \
  '[Install]' \
  'WantedBy=sockets.target'

require_exact_key_assignments Service Type "$service" 'Type=notify'
require_exact_key_assignments Service NotifyAccess "$service" 'NotifyAccess=main'
require_exact_key_assignments Service User "$service" 'User=recasaos-public'
require_exact_key_assignments Service Group "$service" 'Group=recasaos-public'
require_exact_key_assignments Service SupplementaryGroups "$service" 'SupplementaryGroups='
require_exact_key_assignments Service UMask "$service" 'UMask=0077'
require_exact_key_assignments Service RootDirectory "$service" \
  'RootDirectory=/usr/lib/recasaos-public-files/rootfs'
require_exact_key_assignments Service BindReadOnlyPaths "$service" \
  'BindReadOnlyPaths=/srv/recasaos-public:/srv/public:rbind' \
  'BindReadOnlyPaths=/run/systemd/notify:/run/systemd/notify:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.max:/run/recasaos-cgroup/memory.max:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.swap.max:/run/recasaos-cgroup/memory.swap.max:norbind' \
  'BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/pids.max:/run/recasaos-cgroup/pids.max:norbind'
require_exact_key_assignments Service LoadCredential "$service" \
  'LoadCredential=recasaos-public-file-verifier:/etc/recasaos/public-file.verifier'
require_exact_key_assignments Service ExecStart "$service" \
  'ExecStart=/usr/bin/recasaos-public-files serve --activation-name=public-files --listen=127.0.0.1:39777 --root=/srv/public --verifier-file=${CREDENTIALS_DIRECTORY}/recasaos-public-file-verifier'
require_exact_key_assignments Service PrivateNetwork "$service" 'PrivateNetwork=yes'
require_exact_key_assignments Service RestrictAddressFamilies "$service" \
  'RestrictAddressFamilies=AF_UNIX'
require_exact_key_assignments Service IPAddressDeny "$service" 'IPAddressDeny=any'
require_exact_key_assignments Service IPAddressAllow "$service" 'IPAddressAllow=localhost'
require_exact_key_assignments Service PrivateDevices "$service" 'PrivateDevices=yes'
require_exact_key_assignments Service PrivateMounts "$service" 'PrivateMounts=yes'
require_exact_key_assignments Service PrivateTmp "$service" 'PrivateTmp=yes'
require_exact_key_assignments Service ProtectProc "$service" 'ProtectProc=invisible'
require_exact_key_assignments Service ProcSubset "$service" 'ProcSubset=pid'
require_exact_key_assignments Service ProtectSystem "$service" 'ProtectSystem=strict'
require_exact_key_assignments Service ProtectHome "$service" 'ProtectHome=yes'
require_exact_key_assignments Service InaccessiblePaths "$service" \
  'InaccessiblePaths=+/sys -+/dev/shm'
require_exact_key_assignments Service ReadOnlyPaths "$service" \
  'ReadOnlyPaths=+/tmp +/var/tmp'
require_exact_key_assignments Service CapabilityBoundingSet "$service" \
  'CapabilityBoundingSet='
require_exact_key_assignments Service AmbientCapabilities "$service" \
  'AmbientCapabilities='
require_exact_key_assignments Service NoNewPrivileges "$service" \
  'NoNewPrivileges=yes'
require_exact_key_assignments Service SystemCallArchitectures "$service" \
  'SystemCallArchitectures=native'
require_exact_key_assignments Service SystemCallFilter "$service" \
  'SystemCallFilter=@system-service' \
  'SystemCallFilter=~@clock @cpu-emulation @debug @keyring @module @mount @obsolete @privileged @raw-io @reboot @swap clone3 memfd_create'

require_exact_key_assignments Socket ListenStream "$socket" \
  'ListenStream=127.0.0.1:39777'
require_exact_key_assignments Socket Accept "$socket" 'Accept=no'
require_exact_key_assignments Socket Service "$socket" \
  'Service=recasaos-public-files.service'
require_exact_key_assignments Socket FileDescriptorName "$socket" \
  'FileDescriptorName=public-files'
require_exact_key_assignments Socket IPAddressDeny "$socket" 'IPAddressDeny=any'
require_exact_key_assignments Socket IPAddressAllow "$socket" \
  'IPAddressAllow=localhost'

for forbidden_service_key in \
  DynamicUser RestrictSUIDSGID PrivateIPC SocketBindAllow SocketBindDeny \
  BindPaths ReadWritePaths ReadWriteDirectories ReadOnlyDirectories \
  InaccessibleDirectories RootImage RootImageOptions MountImages \
  ExtensionImages TemporaryFileSystem DeviceAllow DevicePolicy \
  ExecStartPre ExecStartPost \
  ExecStop ExecStopPost ExecReload Wants Requires BindsTo PartOf \
  Environment EnvironmentFile PassEnvironment UnsetEnvironment
do
  reject_key_assignments "$forbidden_service_key" "$service"
done
for forbidden_socket_key in \
  ListenDatagram ListenSequentialPacket ListenFIFO ListenSpecial \
  ListenMessageQueue ListenNetlink ListenUSBFunction Wants Requires \
  BindsTo PartOf
do
  reject_key_assignments "$forbidden_socket_key" "$socket"
done
reject_active_pattern '%d/recasaos-public-file-verifier' "$service"
reject_active_pattern 'RECASAOS_PUBLIC_FILE_' "$service"
reject_active_pattern 'RECASAOS_PUBLIC_FILE_' "$socket"
if grep -Ev '^[[:space:]]*(#|$)' "$retired" | grep -q .; then
  fail "$retired must remain comments-only and inert"
fi

require_exact_active_lines "$sysusers" \
  'g recasaos-public -' \
  'u recasaos-public - "ReCasaOS public-file portal" /nonexistent /usr/sbin/nologin'
require_exact_active_lines "$tmpfiles" \
  'd /srv/recasaos-public 0750 root recasaos-public -' \
  'd /usr/lib/recasaos-public-files 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/usr 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/usr/bin 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/srv 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/srv/public 0750 root recasaos-public -' \
  'd /usr/lib/recasaos-public-files/rootfs/proc 0555 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/sys 0555 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/dev 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/run 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/run/systemd 0555 root root -' \
  'f /usr/lib/recasaos-public-files/rootfs/run/systemd/notify 0000 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup 0555 root root -' \
  'f /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/memory.max 0000 root root -' \
  'f /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/memory.swap.max 0000 root root -' \
  'f /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/pids.max 0000 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/tmp 01777 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/var 0755 root root -' \
  'd /usr/lib/recasaos-public-files/rootfs/var/tmp 01777 root root -'

if test "${RECASAOS_SYSTEMD_LIVE_VERIFY:-0}" = 1; then
  command -v cmp >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_LIVE_VERIFY=1 but cmp is unavailable'
  command -v getent >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_LIVE_VERIFY=1 but getent is unavailable'
  command -v id >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_LIVE_VERIFY=1 but id is unavailable'
  command -v readlink >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_LIVE_VERIFY=1 but readlink is unavailable'
  command -v stat >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_LIVE_VERIFY=1 but stat is unavailable'
  command -v systemctl >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_LIVE_VERIFY=1 but systemctl is unavailable'

  live_service=/usr/lib/systemd/system/recasaos-public-files.service
  live_socket=/usr/lib/systemd/system/recasaos-public-files.socket
  live_sysusers=/usr/lib/sysusers.d/recasaos-public-files.conf
  live_tmpfiles=/usr/lib/tmpfiles.d/recasaos-public-files.conf
  candidate_binary="${repo_root}/build/sysroot/usr/lib/recasaos-public-files/rootfs/usr/bin/recasaos-public-files"
  live_binary=/usr/lib/recasaos-public-files/rootfs/usr/bin/recasaos-public-files

  require_live_directory_metadata() {
    live_directory_path=$1
    live_directory_expected=$2
    test -d "$live_directory_path" ||
      fail "installed directory is missing: $live_directory_path"
    test ! -L "$live_directory_path" ||
      fail "installed directory is a symlink: $live_directory_path"
    live_directory_actual=$(
      stat -c '%U:%G:%a' "$live_directory_path"
    )
    test "$live_directory_actual" = "$live_directory_expected" ||
      fail "installed directory metadata is unsafe: $live_directory_path ($live_directory_actual)"
  }

  require_live_file_metadata() {
    live_file_path=$1
    test -f "$live_file_path" ||
      fail "installed placeholder file is missing: $live_file_path"
    test ! -L "$live_file_path" ||
      fail "installed placeholder file is a symlink: $live_file_path"
    live_file_actual=$(
      stat -c '%U:%G:%a:%h:%s' "$live_file_path"
    )
    test "$live_file_actual" = root:root:0:1:0 ||
      fail "installed placeholder metadata is unsafe: $live_file_path ($live_file_actual)"
  }

  for pair in \
    "$service:$live_service" \
    "$socket:$live_socket" \
    "$sysusers:$live_sysusers" \
    "$tmpfiles:$live_tmpfiles" \
    "$candidate_binary:$live_binary"
  do
    candidate=${pair%%:*}
    installed=${pair#*:}
    test -f "$candidate" || fail "missing candidate payload $candidate"
    test ! -L "$candidate" || fail "candidate payload is a symlink: $candidate"
    test -f "$installed" || fail "missing installed payload $installed"
    test ! -L "$installed" || fail "installed payload is a symlink: $installed"
    cmp -s "$candidate" "$installed" ||
      fail "installed payload differs from reviewed candidate: $installed"
  done

  for live_control_file in \
    "$live_service" "$live_socket" "$live_sysusers" "$live_tmpfiles"
  do
    live_control_metadata=$(
      stat -c '%U:%G:%a:%h' "$live_control_file"
    )
    test "$live_control_metadata" = root:root:644:1 ||
      fail "installed control-file metadata is unsafe: $live_control_file ($live_control_metadata)"
  done

  service_uid=$(id -u recasaos-public)
  service_gid=$(id -g recasaos-public)
  case "$service_uid:$service_gid" in
    *[!0-9:]* | 0:* | *:0)
      fail "recasaos-public has a privileged or invalid identity"
      ;;
  esac
  test "$(id -G recasaos-public)" = "$service_gid" ||
    fail 'recasaos-public has unexpected supplementary groups'
  getent passwd recasaos-public |
    awk -F: -v uid="$service_uid" -v gid="$service_gid" '
      NR == 1 {
        valid = (
          $1 == "recasaos-public" &&
          $3 == uid &&
          $4 == gid &&
          $5 == "ReCasaOS public-file portal" &&
          $6 == "/nonexistent" &&
          $7 == "/usr/sbin/nologin"
        )
      }
      END { exit !(NR == 1 && valid) }
    ' ||
    fail 'recasaos-public passwd entry differs from the reviewed identity'
  getent group recasaos-public |
    awk -F: -v gid="$service_gid" '
      NR == 1 {
        valid = (
          $1 == "recasaos-public" &&
          $3 == gid &&
          $4 == ""
        )
      }
      END { exit !(NR == 1 && valid) }
    ' ||
    fail 'recasaos-public group entry differs from the reviewed identity'

  require_live_directory_metadata /etc/recasaos root:root:700
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/usr root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/usr/bin root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/srv root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/srv/public root:recasaos-public:750
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/proc root:root:555
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/sys root:root:555
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/dev root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/run root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/run/systemd root:root:555
  require_live_file_metadata \
    /usr/lib/recasaos-public-files/rootfs/run/systemd/notify
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup root:root:555
  require_live_file_metadata \
    /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/memory.max
  require_live_file_metadata \
    /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/memory.swap.max
  require_live_file_metadata \
    /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/pids.max
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/tmp root:root:1777
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/var root:root:755
  require_live_directory_metadata \
    /usr/lib/recasaos-public-files/rootfs/var/tmp root:root:1777

  for override in \
    /etc/sysusers.d/recasaos-public-files.conf \
    /run/sysusers.d/recasaos-public-files.conf \
    /usr/local/lib/sysusers.d/recasaos-public-files.conf \
    /etc/tmpfiles.d/recasaos-public-files.conf \
    /run/tmpfiles.d/recasaos-public-files.conf \
    /usr/local/lib/tmpfiles.d/recasaos-public-files.conf
  do
    if test -e "$override" || test -L "$override"; then
      fail "higher-priority host override is forbidden: $override"
    fi
  done

  for unit in recasaos-public-files.service recasaos-public-files.socket; do
    load_state=$(systemctl show --property=LoadState --value "$unit")
    test "$load_state" = loaded || fail "$unit is not loaded"
    drop_ins=$(systemctl show --property=DropInPaths --value "$unit")
    test -z "$drop_ins" || fail "$unit has unreviewed drop-ins: $drop_ins"
  done

  actual_service=$(
    systemctl show --property=FragmentPath --value \
      recasaos-public-files.service
  )
  actual_socket=$(
    systemctl show --property=FragmentPath --value \
      recasaos-public-files.socket
  )
  test "$(readlink -f -- "$actual_service")" = \
    "$(readlink -f -- "$live_service")" ||
    fail "service fragment is not the reviewed installed unit: $actual_service"
  test "$(readlink -f -- "$actual_socket")" = \
    "$(readlink -f -- "$live_socket")" ||
    fail "socket fragment is not the reviewed installed unit: $actual_socket"

  service_state=$(
    systemctl show --property=ActiveState --value \
      recasaos-public-files.service
  )
  socket_state=$(
    systemctl show --property=ActiveState --value \
      recasaos-public-files.socket
  )
  socket_file_state=$(
    systemctl show --property=UnitFileState --value \
      recasaos-public-files.socket
  )
  test "$service_state" = inactive ||
    fail "service must be inactive during staging, got $service_state"
  test "$socket_state" = inactive ||
    fail "socket must be inactive during staging, got $socket_state"
  test "$socket_file_state" = disabled ||
    fail "socket must be disabled during staging, got $socket_file_state"

  test -f /etc/recasaos/public-file.verifier ||
    fail 'installed verifier is not a regular file'
  test ! -L /etc/recasaos/public-file.verifier ||
    fail 'installed verifier must not be a symlink'
  test -d /srv/recasaos-public ||
    fail 'installed public share is not a directory'
  test ! -L /srv/recasaos-public ||
    fail 'installed public share must not be a symlink'
  verifier_metadata=$(
    stat -c '%U:%G:%a:%h:%s' /etc/recasaos/public-file.verifier
  )
  test "$verifier_metadata" = root:root:600:1:100 ||
    fail "installed verifier metadata is unsafe: $verifier_metadata"
  share_metadata=$(stat -c '%U:%G:%a' /srv/recasaos-public)
  test "$share_metadata" = root:recasaos-public:750 ||
    fail "installed share metadata is unsafe: $share_metadata"
  binary_metadata=$(stat -c '%U:%G:%a:%h' "$live_binary")
  test "$binary_metadata" = root:root:755:1 ||
    fail "installed binary metadata is unsafe: $binary_metadata"
fi

if test "${RECASAOS_SYSTEMD_VERIFY:-0}" = 1; then
  command -v systemd-analyze >/dev/null 2>&1 ||
    fail 'RECASAOS_SYSTEMD_VERIFY=1 but systemd-analyze is unavailable'
  test "${RECASAOS_SYSTEMD_LIVE_VERIFY:-0}" = 1 ||
    fail 'RECASAOS_SYSTEMD_VERIFY=1 requires RECASAOS_SYSTEMD_LIVE_VERIFY=1'
  "$semantic_verifier" "$live_service" "$live_socket" "$live_binary"
fi

printf '%s\n' 'public-files unit check: passed'
