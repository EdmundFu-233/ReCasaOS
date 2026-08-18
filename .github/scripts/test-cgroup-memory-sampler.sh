#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'cgroup memory sampler test failed: %s\n' "$*" >&2
  exit 1
}

publish_fixture_sample() {
  local path=$1
  local value=$2

  [[ "$value" =~ ^[0-9]{3}$ ]] || fail "unsafe fixture sample value"
  python3 - "$path" "$value" <<'PYTHON'
import os
import stat
import sys

path = sys.argv[1]
payload = f"{sys.argv[2]}\n".encode("ascii")
flags = os.O_WRONLY | os.O_CLOEXEC
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags)
try:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size != len(payload)
    ):
        raise SystemExit("unsafe memory.current fixture metadata")
    written = os.pwrite(descriptor, payload, 0)
    if written != len(payload):
        raise SystemExit("short memory.current fixture write")
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PYTHON
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
sampler="$script_dir/sample-cgroup-memory.py"
workspace="$(mktemp -d)"
sampler_pid=

sampler_job_is_running() {
  local running_pid

  [[ "$sampler_pid" =~ ^[1-9][0-9]*$ ]] || return 1
  while IFS= read -r running_pid; do
    [[ "$running_pid" == "$sampler_pid" ]] && return 0
  done < <(jobs -pr)
  return 1
}

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if sampler_job_is_running; then
    kill -TERM "$sampler_pid" 2>/dev/null || true
  fi
  if [[ "$sampler_pid" =~ ^[1-9][0-9]*$ ]]; then
    wait "$sampler_pid" 2>/dev/null || true
  fi
  rm -rf -- "$workspace"
  exit "$status"
}
trap cleanup EXIT

[[ -f "$sampler" && ! -L "$sampler" ]] || fail "sampler source is unavailable"
PYTHONPYCACHEPREFIX="$workspace/pycache" python3 -m py_compile "$sampler"

source_file="$workspace/memory.current"
output_file="$workspace/peak"
ready_file="$workspace/ready"
stop_file="$workspace/stop"
failure_file="$workspace/failure"
printf '100\n' >"$source_file"
chmod 0600 "$source_file"
python3 "$sampler" \
  "$source_file" "$output_file" "$ready_file" "$stop_file" \
  2>"$failure_file" &
sampler_pid=$!

deadline=$((SECONDS + 5))
while [[ ! -s "$ready_file" ]]; do
  ((SECONDS < deadline)) || fail "sampler did not become ready"
  sampler_job_is_running || {
    sed -n '1,20p' "$failure_file" >&2
    fail "sampler exited before becoming ready"
  }
  sleep 0.02
done

publish_fixture_sample "$source_file" 500
while [[ "$(<"$ready_file")" != 500 ]]; do
  ((SECONDS < deadline)) || fail "sampler did not observe the high-water value"
  sleep 0.02
done
publish_fixture_sample "$source_file" 300
install -m 0600 /dev/null "$stop_file"
wait "$sampler_pid" || {
  sed -n '1,20p' "$failure_file" >&2
  fail "sampler failed during the positive case"
}
sampler_pid=
[[ "$(<"$output_file")" == 500 ]] ||
  fail "sampled peak is $(<"$output_file"), want 500"
python3 - "$ready_file" "$output_file" <<'PYTHON'
import os
import stat
import sys

for path in sys.argv[1:]:
    metadata = os.lstat(path)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
    ):
        raise SystemExit(f"unsafe sampler result metadata: {path}")
PYTHON

unsafe_stop_dir="$workspace/unsafe-stop"
mkdir "$unsafe_stop_dir"
printf '1\n' >"$unsafe_stop_dir/memory.current"
python3 "$sampler" \
  "$unsafe_stop_dir/memory.current" \
  "$unsafe_stop_dir/peak" \
  "$unsafe_stop_dir/ready" \
  "$unsafe_stop_dir/stop" \
  2>"$unsafe_stop_dir/failure" &
sampler_pid=$!
deadline=$((SECONDS + 5))
while [[ ! -s "$unsafe_stop_dir/ready" ]]; do
  ((SECONDS < deadline)) || fail "unsafe-stop sampler did not become ready"
  sampler_job_is_running ||
    fail "unsafe-stop sampler exited before becoming ready"
  sleep 0.02
done
install -m 0644 /dev/null "$unsafe_stop_dir/stop"
if wait "$sampler_pid"; then
  fail "sampler accepted an unsafe stop marker"
fi
sampler_pid=
grep -Fq 'stop marker metadata is unsafe' "$unsafe_stop_dir/failure" ||
  fail "unsafe stop marker did not produce the expected rejection"

malformed_dir="$workspace/malformed"
mkdir "$malformed_dir"
printf 'not-a-number\n' >"$malformed_dir/memory.current"
if python3 "$sampler" \
  "$malformed_dir/memory.current" \
  "$malformed_dir/peak" \
  "$malformed_dir/ready" \
  "$malformed_dir/stop" \
  >/dev/null 2>&1; then
  fail "malformed source unexpectedly succeeded"
fi

symlink_dir="$workspace/symlink"
mkdir "$symlink_dir"
printf '1\n' >"$symlink_dir/real"
ln -s real "$symlink_dir/memory.current"
if python3 "$sampler" \
  "$symlink_dir/memory.current" \
  "$symlink_dir/peak" \
  "$symlink_dir/ready" \
  "$symlink_dir/stop" \
  >/dev/null 2>&1; then
  fail "symlink source unexpectedly succeeded"
fi

preexisting_dir="$workspace/preexisting"
mkdir "$preexisting_dir"
printf '1\n' >"$preexisting_dir/memory.current"
install -m 0600 /dev/null "$preexisting_dir/peak"
if python3 "$sampler" \
  "$preexisting_dir/memory.current" \
  "$preexisting_dir/peak" \
  "$preexisting_dir/ready" \
  "$preexisting_dir/stop" \
  >/dev/null 2>&1; then
  fail "preexisting output unexpectedly succeeded"
fi

printf 'cgroup memory sampler tests passed\n'
