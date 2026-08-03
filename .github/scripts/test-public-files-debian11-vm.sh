#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Debian 11 systemd VM test failed: %s\n' "$*" >&2
  exit 1
}

[[ "${RECASAOS_DEBIAN11_VM_CI:-0}" == 1 ]] ||
  fail "explicit Debian VM CI opt-in is missing"
[[ "${GITHUB_ACTIONS:-}" == true ]] ||
  fail "this VM test is restricted to GitHub Actions"
[[ "${GITHUB_REPOSITORY:-}" == EdmundFu-233/ReCasaOS ]] ||
  fail "the repository identity is not the trusted ReCasaOS repository"
[[ "${RUNNER_OS:-}" == Linux ]] || fail "the runner is not Linux"
[[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted ]] ||
  fail "GitHub did not identify this as a hosted runner"
[[ -d /opt/hostedtoolcache ]] ||
  fail "the GitHub-hosted runner marker is missing"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ID is missing or unsafe"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ATTEMPT is missing or unsafe"
[[ "${RECASAOS_EXPECTED_SHA:-}" =~ ^[0-9a-f]{40}$ ]] ||
  fail "the expected commit SHA is missing or unsafe"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd -- "$repo_root"
[[ "$(git rev-parse --show-toplevel)" == "$repo_root" ]] ||
  fail "the script is not running from the exact repository root"
actual_sha="$(git rev-parse HEAD)" || fail "could not inspect the checkout SHA"
[[ "$actual_sha" == "$RECASAOS_EXPECTED_SHA" ]] ||
  fail "checkout SHA $actual_sha does not match $RECASAOS_EXPECTED_SHA"
[[ -z "$(git status --porcelain=v1 --untracked-files=all)" ]] ||
  fail "the exact checkout is not clean"

for required_tool in \
  cloud-localds curl git go python3 qemu-img qemu-system-x86_64 \
  scp sha256sum sha512sum ssh ssh-keygen tar timeout
do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "required VM test tool is unavailable: $required_tool"
done
[[ "$(go version)" == "go version go1.26.5 linux/amd64" ]] ||
  fail "the host Go toolchain is not exact Go 1.26.5 linux/amd64"
/usr/bin/python3 -c '
import os
import signal

if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
    raise SystemExit(1)
' || fail "host Python pidfd signaling support is unavailable"

runner_temp="$(cd -- "${RUNNER_TEMP:?RUNNER_TEMP is missing}" && pwd -P)"
[[ "$runner_temp" == /* && -d "$runner_temp" && ! -L "$runner_temp" ]] ||
  fail "RUNNER_TEMP is not a safe physical directory"
workspace="$(mktemp -d "$runner_temp/recasaos-debian11-vm.XXXXXX")"
case "$workspace" in
  "$runner_temp"/recasaos-debian11-vm.[A-Za-z0-9]*) ;;
  *) fail "refusing unsafe VM workspace path: $workspace" ;;
esac

base_image="$workspace/debian-11-generic-amd64.qcow2"
overlay_image="$workspace/debian-11-overlay.qcow2"
seed_image="$workspace/debian-11-seed.img"
user_data="$workspace/user-data"
meta_data="$workspace/meta-data"
private_key="$workspace/guest-key"
known_hosts="$workspace/known-hosts"
serial_log="$workspace/serial.log"
qemu_log="$workspace/qemu.log"
repo_archive="$workspace/recasaos.tar"
go_archive="$workspace/go.tar.gz"
payload_manifest="$workspace/payload.sha256"
run_key="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
guest_payload="/tmp/recasaos-vm-payload-${run_key}"
image_url='https://cloud.debian.org/images/cloud/bullseye/20260728-2553/debian-11-generic-amd64-20260728-2553.qcow2'
image_sha512='67dcf10dc67b807596c21b36fcd0a752838c124420774737d4badc46cb115b88cc879fac91a22d149d74b2ecd9600a7b4761690900348726e718f501a8564131'
qemu_pid=
qemu_start_time=

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

qemu_process_is_live() {
  local current_start_time

  [[ "$qemu_pid" =~ ^[0-9]+$ && "$qemu_pid" -gt 1 &&
    "$qemu_start_time" =~ ^[0-9]+$ ]] || return 1
  current_start_time="$(process_start_time "$qemu_pid" 2>/dev/null)" ||
    return 1
  [[ "$current_start_time" == "$qemu_start_time" ]]
}

signal_exact_process() {
  local pid=$1
  local start_time=$2
  local signal_number=$3

  [[ "$pid" =~ ^[0-9]+$ && "$pid" -gt 1 &&
    "$start_time" =~ ^[0-9]+$ &&
    ( "$signal_number" == 9 || "$signal_number" == 15 ) ]] || return 1
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

cleanup() {
  status=$?
  cleanup_status=0
  trap - EXIT
  set +e

  if qemu_process_is_live; then
    signal_exact_process "$qemu_pid" "$qemu_start_time" 15 ||
      cleanup_status=1
    deadline=$((SECONDS + 10))
    while qemu_process_is_live && ((SECONDS < deadline)); do
      sleep 0.1
    done
  fi
  if qemu_process_is_live; then
    signal_exact_process "$qemu_pid" "$qemu_start_time" 9 ||
      cleanup_status=1
    deadline=$((SECONDS + 5))
    while qemu_process_is_live && ((SECONDS < deadline)); do
      sleep 0.1
    done
  fi
  if qemu_process_is_live; then
    printf 'Debian VM cleanup could not stop the exact QEMU process\n' >&2
    cleanup_status=1
  elif [[ "$qemu_pid" =~ ^[0-9]+$ ]]; then
    wait "$qemu_pid" 2>/dev/null || true
  fi

  if [[ "$status" != 0 ]]; then
    if [[ -s "$qemu_log" ]]; then
      printf '%s\n' 'QEMU diagnostics:' >&2
      tail -n 120 "$qemu_log" >&2
    fi
    if [[ -s "$serial_log" ]]; then
      printf '%s\n' 'Debian guest serial diagnostics:' >&2
      tail -n 200 "$serial_log" >&2
    fi
  fi

  case "$workspace" in
    "$runner_temp"/recasaos-debian11-vm.[A-Za-z0-9]*)
      if [[ -d "$workspace" && ! -L "$workspace" ]]; then
        rm -rf -- "$workspace" || cleanup_status=1
      elif [[ -e "$workspace" || -L "$workspace" ]]; then
        printf 'refusing unsafe VM workspace cleanup: %s\n' "$workspace" >&2
        cleanup_status=1
      fi
      ;;
    *)
      printf 'refusing unsafe VM workspace cleanup: %s\n' "$workspace" >&2
      cleanup_status=1
      ;;
  esac

  if [[ "$status" == 0 && "$cleanup_status" != 0 ]]; then
    status=1
  fi
  exit "$status"
}
trap cleanup EXIT

curl --fail --location --proto '=https' --tlsv1.2 \
  --retry 3 --retry-all-errors --connect-timeout 20 --max-time 600 \
  --output "$base_image" "$image_url"
printf '%s  %s\n' "$image_sha512" "$base_image" |
  sha512sum --check --status || fail "Debian cloud image checksum mismatch"
qemu-img info --output=json "$base_image" >"$workspace/base-image.json"
/usr/bin/python3 - "$workspace/base-image.json" <<'PYTHON'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    info = json.load(source)
if info.get("format") != "qcow2":
    raise SystemExit("base image is not qcow2")
if info.get("backing-filename") is not None:
    raise SystemExit("base image unexpectedly has a backing file")
size = info.get("virtual-size")
if not isinstance(size, int) or not 1_000_000_000 <= size <= 20_000_000_000:
    raise SystemExit("base image virtual size is outside the reviewed bound")
PYTHON

qemu-img create -f qcow2 -F qcow2 -b "$base_image" "$overlay_image"
qemu-img resize "$overlay_image" 8G
qemu-img info --output=json "$overlay_image" >"$workspace/overlay-image.json"
/usr/bin/python3 - "$workspace/overlay-image.json" "$base_image" <<'PYTHON'
import json
import os
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    info = json.load(source)
if info.get("format") != "qcow2":
    raise SystemExit("overlay image is not qcow2")
backing = info.get("full-backing-filename")
if backing is None or os.path.realpath(backing) != os.path.realpath(sys.argv[2]):
    raise SystemExit("overlay image does not use the reviewed base image")
if info.get("virtual-size") != 8 * 1024 * 1024 * 1024:
    raise SystemExit("overlay image virtual size is not exactly 8 GiB")
PYTHON

umask 077
ssh-keygen -q -t ed25519 -N '' -f "$private_key"
guest_public_key="$(<"${private_key}.pub")"
[[ "$guest_public_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+\ .+$ ]] ||
  fail "generated guest SSH public key is malformed"
cat >"$user_data" <<EOF
#cloud-config
users:
  - name: debian
    gecos: ReCasaOS CI
    groups: [adm, sudo]
    shell: /bin/bash
    lock_passwd: true
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $guest_public_key
ssh_pwauth: false
disable_root: true
package_update: true
package_upgrade: false
packages:
  - acl
  - ca-certificates
  - curl
  - dmsetup
  - e2fsprogs
  - file
  - iproute2
  - kmod
  - procps
  - sudo
  - udev
  - util-linux
EOF
cat >"$meta_data" <<EOF
instance-id: recasaos-${run_key}
local-hostname: recasaos-debian11-ci
EOF
cloud-localds "$seed_image" "$user_data" "$meta_data"

host_goroot="$(cd -- "$(go env GOROOT)" && pwd -P)"
case "$host_goroot" in
  /opt/hostedtoolcache/go/1.26.5/*) ;;
  *) fail "host Go root is outside the pinned hosted toolcache" ;;
esac
tar -C "$host_goroot" -czf "$go_archive" .
git archive --format=tar --prefix=recasaos-src/ \
  --output="$repo_archive" "$RECASAOS_EXPECTED_SHA"
go_payload_hash="$(sha256sum "$go_archive" | awk '{print $1}')"
repo_payload_hash="$(sha256sum "$repo_archive" | awk '{print $1}')"
[[ "$go_payload_hash" =~ ^[0-9a-f]{64}$ &&
  "$repo_payload_hash" =~ ^[0-9a-f]{64}$ ]] ||
  fail "could not hash the VM payload"
printf '%s  go.tar.gz\n%s  recasaos.tar\n' \
  "$go_payload_hash" "$repo_payload_hash" >"$payload_manifest"

ssh_port="$(/usr/bin/python3 - <<'PYTHON'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    print(listener.getsockname()[1])
PYTHON
)"
[[ "$ssh_port" =~ ^[0-9]+$ && "$ssh_port" -ge 1024 &&
  "$ssh_port" -le 65535 ]] || fail "could not allocate a safe SSH port"

qemu-system-x86_64 \
  -name recasaos-debian11-ci \
  -machine pc \
  -accel tcg,thread=multi \
  -cpu max \
  -smp 2 \
  -m 2048 \
  -display none \
  -monitor none \
  -serial "file:$serial_log" \
  -no-reboot \
  -drive "if=virtio,format=qcow2,file=$overlay_image" \
  -drive "if=virtio,format=raw,readonly=on,file=$seed_image" \
  -netdev "user,id=net0,hostfwd=tcp:127.0.0.1:${ssh_port}-:22" \
  -device virtio-net-pci,netdev=net0 \
  -device virtio-rng-pci \
  >"$qemu_log" 2>&1 &
qemu_pid=$!
qemu_start_time="$(process_start_time "$qemu_pid")" ||
  fail "could not record the exact QEMU process identity"

ssh_common=(
  -i "$private_key"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o IdentitiesOnly=yes
  -o LogLevel=ERROR
  -o StrictHostKeyChecking=accept-new
  -o "UserKnownHostsFile=$known_hosts"
)
ssh_deadline=$((SECONDS + 600))
until ssh "${ssh_common[@]}" -p "$ssh_port" \
  debian@127.0.0.1 true >/dev/null 2>&1
do
  qemu_process_is_live || fail "QEMU exited before SSH became ready"
  ((SECONDS < ssh_deadline)) || fail "timed out waiting for guest SSH"
  sleep 2
done

timeout --signal=TERM --kill-after=10s 10m \
  ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
    'sudo cloud-init status --wait --long' || {
      ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
        'sudo cloud-init status --long || true; sudo journalctl --no-pager -u cloud-final.service -n 120 || true' \
        >&2 || true
      fail "cloud-init did not complete successfully"
    }

guest_identity="$(
  ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 '
    set -eu
    . /etc/os-release
    printf "%s:%s\n" "${ID:-}" "${VERSION_ID:-}"
    cat /proc/1/comm
    systemd --version | sed -n "1p"
    systemctl show --property=Version --value
    systemd-detect-virt --vm
    stat -fc %T /sys/fs/cgroup
    uname -r
    df -B1 --output=size / | awk "NR == 2 { gsub(/[[:space:]]/, \"\"); print }"
    dpkg --compare-versions "$(uname -r | cut -d- -f1)" ge 5.8
  '
)" || fail "could not verify the guest platform identity"
guest_release="$(sed -n '1p' <<<"$guest_identity")"
guest_pid1="$(sed -n '2p' <<<"$guest_identity")"
guest_systemd="$(sed -n '3p' <<<"$guest_identity")"
guest_manager="$(sed -n '4p' <<<"$guest_identity")"
guest_virt="$(sed -n '5p' <<<"$guest_identity")"
guest_cgroup="$(sed -n '6p' <<<"$guest_identity")"
guest_kernel="$(sed -n '7p' <<<"$guest_identity")"
guest_root_bytes="$(sed -n '8p' <<<"$guest_identity")"
[[ "$guest_release" == debian:11 ]] ||
  fail "guest release is $guest_release, want debian:11"
[[ "$guest_pid1" == systemd ]] || fail "guest PID 1 is not systemd"
[[ "$guest_systemd" == systemd\ 247* ]] ||
  fail "guest systemd is $guest_systemd, want version 247"
[[ "$guest_manager" == 247* ]] ||
  fail "guest manager is $guest_manager, want version 247"
[[ "$guest_virt" == qemu ]] || fail "guest virtualization is not QEMU"
[[ "$guest_cgroup" == cgroup2fs ]] ||
  fail "guest is not using unified cgroup v2"
[[ "$guest_root_bytes" =~ ^[0-9]+$ &&
  "$guest_root_bytes" -ge 6442450944 ]] ||
  fail "guest root filesystem did not grow to the reviewed minimum"
printf 'verified Debian 11 VM: %s; binary %s; manager %s; kernel %s; %s; root=%s bytes\n' \
  "$guest_release" "$guest_systemd" "$guest_manager" "$guest_kernel" \
  "$guest_cgroup" "$guest_root_bytes"

ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
  "install -d -m 0700 '$guest_payload'"
scp "${ssh_common[@]}" -P "$ssh_port" \
  "$go_archive" "$repo_archive" "$payload_manifest" \
  "debian@127.0.0.1:${guest_payload}/"
ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
  /bin/bash -s -- "$guest_payload" <<'REMOTE_SETUP'
set -euo pipefail
IFS=$'\n\t'
payload=$1
[[ "$payload" =~ ^/tmp/recasaos-vm-payload-[0-9]+-[0-9]+$ ]] ||
  { printf 'unsafe guest payload path: %s\n' "$payload" >&2; exit 1; }
cd -- "$payload"
sha256sum --check payload.sha256
sudo test ! -e /usr/local/go
sudo test ! -e /opt/recasaos-src
sudo install -d -o root -g root -m 0755 /usr/local/go
sudo tar -C /usr/local/go -xzf go.tar.gz
sudo tar -C /opt -xf recasaos.tar
sudo chown -R debian:debian /opt/recasaos-src
test "$(/usr/local/go/bin/go version)" = \
  'go version go1.26.5 linux/amd64'
REMOTE_SETUP

timeout --signal=TERM --kill-after=120s 22m \
  ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
    env -i \
      HOME=/home/debian \
      USER=debian \
      LOGNAME=debian \
      SHELL=/bin/bash \
      PATH=/usr/local/go/bin:/usr/sbin:/usr/bin:/sbin:/bin \
      GOTOOLCHAIN=local \
      GOCACHE=/home/debian/.cache/go-build \
      GOPATH=/home/debian/go \
      CI=true \
      GITHUB_ACTIONS=true \
      GITHUB_REPOSITORY=EdmundFu-233/ReCasaOS \
      GITHUB_RUN_ID="$GITHUB_RUN_ID" \
      GITHUB_RUN_ATTEMPT="$GITHUB_RUN_ATTEMPT" \
      GITHUB_WORKSPACE=/opt/recasaos-src \
      RUNNER_OS=Linux \
      RECASAOS_TRUSTED_SYSTEMD_CI=1 \
      RECASAOS_HOSTILE_STORAGE_VM_CI=1 \
      RECASAOS_RUNNER_ENVIRONMENT=github-hosted-vm \
      RECASAOS_SYSTEMD_TEST_TARGET=debian-11-systemd-247-qemu \
      /bin/bash --noprofile --norc \
        /opt/recasaos-src/.github/scripts/test-public-files-systemd.sh

ssh "${ssh_common[@]}" -p "$ssh_port" debian@127.0.0.1 \
  'sudo systemctl poweroff' >/dev/null 2>&1 || true
shutdown_deadline=$((SECONDS + 90))
while qemu_process_is_live && ((SECONDS < shutdown_deadline)); do
  sleep 1
done
qemu_process_is_live && fail "QEMU did not exit after guest poweroff"
if wait "$qemu_pid"; then
  qemu_status=0
else
  qemu_status=$?
fi
qemu_pid=
qemu_start_time=
[[ "$qemu_status" == 0 ]] ||
  fail "QEMU exited with status $qemu_status after guest poweroff"

printf 'Debian 11 systemd 247 PID1 VM integration passed for %s\n' \
  "$RECASAOS_EXPECTED_SHA"
