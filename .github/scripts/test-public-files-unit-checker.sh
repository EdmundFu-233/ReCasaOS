#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files unit checker test failed: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
checker="$repo_root/deploy/systemd/check-public-files-units.sh"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-unit-checker.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

copy_fixture() {
  local fixture="$1"
  install -d \
    "$fixture/build/sysroot/usr/lib/systemd/system" \
    "$fixture/build/sysroot/usr/lib/sysusers.d" \
    "$fixture/build/sysroot/usr/lib/tmpfiles.d" \
    "$fixture/deploy/systemd"
  install -m 0644 \
    "$repo_root/build/sysroot/usr/lib/systemd/system/recasaos-public-files.service" \
    "$fixture/build/sysroot/usr/lib/systemd/system/recasaos-public-files.service"
  install -m 0644 \
    "$repo_root/build/sysroot/usr/lib/systemd/system/recasaos-public-files.socket" \
    "$fixture/build/sysroot/usr/lib/systemd/system/recasaos-public-files.socket"
  install -m 0644 \
    "$repo_root/build/sysroot/usr/lib/sysusers.d/recasaos-public-files.conf" \
    "$fixture/build/sysroot/usr/lib/sysusers.d/recasaos-public-files.conf"
  install -m 0644 \
    "$repo_root/build/sysroot/usr/lib/tmpfiles.d/recasaos-public-files.conf" \
    "$fixture/build/sysroot/usr/lib/tmpfiles.d/recasaos-public-files.conf"
  install -m 0644 \
    "$repo_root/deploy/systemd/recasaos-public-files-verifier.conf.example" \
    "$fixture/deploy/systemd/recasaos-public-files-verifier.conf.example"
  install -m 0755 \
    "$repo_root/deploy/systemd/verify-public-files-units.sh" \
    "$fixture/deploy/systemd/verify-public-files-units.sh"
}

expect_rejected() {
  local name="$1"
  local fixture="$work_dir/$name"
  local service
  local socket
  local sysusers
  local tmpfiles
  local semantic_verifier

  copy_fixture "$fixture"
  service="$fixture/build/sysroot/usr/lib/systemd/system/recasaos-public-files.service"
  socket="$fixture/build/sysroot/usr/lib/systemd/system/recasaos-public-files.socket"
  sysusers="$fixture/build/sysroot/usr/lib/sysusers.d/recasaos-public-files.conf"
  tmpfiles="$fixture/build/sysroot/usr/lib/tmpfiles.d/recasaos-public-files.conf"
  semantic_verifier="$fixture/deploy/systemd/verify-public-files-units.sh"

  case "$name" in
    duplicate-root)
      printf '\n[Service]\nRootDirectory=/\n' >>"$service"
      ;;
    writable-bind)
      printf '\n[Service]\nBindPaths=/etc:/srv/public\n' >>"$service"
      ;;
    missing-cgroup-limit-bind)
      sed \
        '\|^BindReadOnlyPaths=/sys/fs/cgroup/system.slice/recasaos-public-files.service/memory.swap.max:/run/recasaos-cgroup/memory.swap.max:norbind$|d' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    recursive-cgroup-limit-bind)
      sed \
        's|:/run/recasaos-cgroup/pids.max:norbind$|:/run/recasaos-cgroup/pids.max:rbind|' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    missing-cgroup-limit-target)
      sed \
        '\|^f /usr/lib/recasaos-public-files/rootfs/run/recasaos-cgroup/memory.max 0000 root root -$|d' \
        "$tmpfiles" >"$tmpfiles.next"
      mv -f -- "$tmpfiles.next" "$tmpfiles"
      ;;
    host-relative-isolation)
      sed \
        's|InaccessiblePaths=+/sys -+/dev/shm|InaccessiblePaths=-/sys -/dev/shm|' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    optional-sys-isolation)
      sed \
        's|InaccessiblePaths=+/sys -+/dev/shm|InaccessiblePaths=-+/sys -+/dev/shm|' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    temporary-sysfs-mask)
      printf '\n[Service]\nTemporaryFileSystem=/sys:ro\n' >>"$service"
      ;;
    reset-inaccessible-paths)
      printf '\n[Service]\nInaccessiblePaths=\n' >>"$service"
      ;;
    host-relative-temporary-paths)
      sed \
        's|ReadOnlyPaths=+/tmp +/var/tmp|ReadOnlyPaths=/tmp /var/tmp|' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    extra-credential)
      printf '\n[Service]\nLoadCredential=extra:/etc/shadow\n' >>"$service"
      ;;
    extra-listener)
      printf '\n[Socket]\nListenStream=0.0.0.0:39778\n' >>"$socket"
      ;;
    extra-user)
      printf 'u recasaos-extra - "unexpected" /nonexistent /usr/sbin/nologin\n' \
        >>"$sysusers"
      ;;
    extra-tmpfiles-path)
      printf 'd /etc/recasaos-unexpected 0755 root root -\n' >>"$tmpfiles"
      ;;
    candidate-symlink)
      rm -f -- "$service"
      ln -s recasaos-public-files.socket "$service"
      ;;
    wrong-socket-section)
      awk '
        $0 == "TriggerLimitBurst=3" { next }
        $0 == "[Install]" {
          print
          print "TriggerLimitBurst=3"
          next
        }
        { print }
      ' "$socket" >"$socket.next"
      mv -f -- "$socket.next" "$socket"
      ;;
    swapped-syscall-filter-order)
      awk '
        $0 == "SystemCallFilter=@system-service" {
          allowlist = $0
          next
        }
        /^SystemCallFilter=~@clock / {
          print
          print allowlist
          allowlist = ""
          next
        }
        { print }
        END {
          if (allowlist != "")
            exit 1
        }
      ' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    wrong-readiness-type)
      sed 's/^Type=notify$/Type=exec/' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    missing-notify-access)
      sed '/^NotifyAccess=main$/d' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    missing-cgroup-v2-gate)
      sed '/^ConditionPathExists=\/sys\/fs\/cgroup\/cgroup.controllers$/d' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    missing-socket-cgroup-v2-gate)
      sed '/^ConditionPathExists=\/sys\/fs\/cgroup\/memory.swap.max$/d' \
        "$socket" >"$socket.next"
      mv -f -- "$socket.next" "$socket"
      ;;
    reduced-memory-budget)
      sed 's/^MemoryMax=512M$/MemoryMax=256M/' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    reduced-task-budget)
      sed 's/^TasksMax=256$/TasksMax=128/' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    expanded-fd-budget)
      sed 's/^LimitNOFILE=512$/LimitNOFILE=1024/' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    enabled-swap)
      sed 's/^MemorySwapMax=0$/MemorySwapMax=512M/' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    process-only-kill-mode)
      sed 's/^KillMode=control-group$/KillMode=process/' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    allow-clone3)
      sed 's/ @swap clone3 memfd_create$/ @swap memfd_create/' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    unsupported-regular-file-condition)
      sed \
        's|ConditionFileNotEmpty=/etc/recasaos/public-file.verifier|ConditionPathIsRegular=/etc/recasaos/public-file.verifier|' \
        "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    missing-semantic-verifier)
      rm -f -- "$semantic_verifier"
      ;;
    linked-semantic-verifier)
      rm -f -- "$semantic_verifier"
      ln -s -- recasaos-public-files-verifier.conf.example "$semantic_verifier"
      ;;
    nonexecutable-semantic-verifier)
      chmod 0644 "$semantic_verifier"
      ;;
    comment-continuation)
      awk '
        $0 == "CapabilityBoundingSet=" {
          print "# systemd would swallow the next physical line \\"
        }
        { print }
      ' "$service" >"$service.next"
      mv -f -- "$service.next" "$service"
      ;;
    *)
      fail "unknown negative fixture: $name"
      ;;
  esac

  if "$checker" "$fixture" >/dev/null 2>&1; then
    fail "checker accepted unsafe fixture: $name"
  fi
}

"$checker" "$repo_root" >/dev/null
expect_rejected duplicate-root
expect_rejected writable-bind
expect_rejected missing-cgroup-limit-bind
expect_rejected recursive-cgroup-limit-bind
expect_rejected missing-cgroup-limit-target
expect_rejected host-relative-isolation
expect_rejected optional-sys-isolation
expect_rejected temporary-sysfs-mask
expect_rejected reset-inaccessible-paths
expect_rejected host-relative-temporary-paths
expect_rejected extra-credential
expect_rejected extra-listener
expect_rejected extra-user
expect_rejected extra-tmpfiles-path
expect_rejected candidate-symlink
expect_rejected wrong-socket-section
expect_rejected swapped-syscall-filter-order
expect_rejected wrong-readiness-type
expect_rejected missing-notify-access
expect_rejected missing-cgroup-v2-gate
expect_rejected missing-socket-cgroup-v2-gate
expect_rejected reduced-memory-budget
expect_rejected reduced-task-budget
expect_rejected expanded-fd-budget
expect_rejected enabled-swap
expect_rejected process-only-kill-mode
expect_rejected allow-clone3
expect_rejected unsupported-regular-file-condition
expect_rejected missing-semantic-verifier
expect_rejected linked-semantic-verifier
expect_rejected nonexecutable-semantic-verifier
expect_rejected comment-continuation

printf '%s\n' 'public-files unit checker negative tests: passed'
