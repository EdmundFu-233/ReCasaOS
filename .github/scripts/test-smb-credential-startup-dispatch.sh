#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'SMB credential startup dispatch test failed: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-smb-startup-dispatch.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT
binary="$work_root/casaos"

(
  cd -- "$repo_root"
  go build -trimpath -o "$binary" .
)

version_stdout="$work_root/version.stdout"
version_stderr="$work_root/version.stderr"
if ! env CREDENTIALS_DIRECTORY= "$binary" -v >"$version_stdout" 2>"$version_stderr"; then
  fail 'version mode reached credential admission'
fi
[[ "$(wc -l <"$version_stdout" | tr -d '[:space:]')" == 1 ]] ||
  fail 'version mode produced unexpected stdout'
grep -Eq '^v[^[:space:]]+$' "$version_stdout" || fail 'version mode did not print one version'
[[ ! -s "$version_stderr" ]] || fail 'version mode produced stderr'

probe_stdout="$work_root/probe.stdout"
probe_stderr="$work_root/probe.stderr"
set +e
env CREDENTIALS_DIRECTORY= timeout 5s "$binary" --internal-samba-probe \
  </dev/null >"$probe_stdout" 2>"$probe_stderr"
probe_status=$?
set -e
[[ "$probe_status" != 124 ]] || fail 'exact internal probe timed out'
! grep -Fq 'admit ReCasaOS SMB systemd credential' "$probe_stderr" ||
  fail 'exact internal probe reached credential admission'
[[ -s "$probe_stdout" ]] || fail 'exact internal probe produced no protocol output'

expect_admission_failure() {
  local name=$1
  shift
  local stdout="$work_root/$name.stdout"
  local stderr="$work_root/$name.stderr"
  set +e
  env CREDENTIALS_DIRECTORY= "$binary" "$@" >"$stdout" 2>"$stderr"
  local status=$?
  set -e
  [[ "$status" != 0 ]] || fail "$name unexpectedly bypassed configured-invalid admission"
  grep -Fq 'admit ReCasaOS SMB systemd credential' "$stderr" ||
    fail "$name did not fail at credential admission"
  [[ ! -s "$stdout" ]] || fail "$name produced stdout before credential admission"
  ! grep -Fq 'git commit:' "$stderr" ||
    fail "$name reached application initialization before credential admission"
  ! grep -Fq 'build date:' "$stderr" ||
    fail "$name reached application initialization before credential admission"
}

expect_admission_failure normal
expect_admission_failure probe-extra --internal-samba-probe unexpected
expect_admission_failure probe-bool --internal-samba-probe=true
expect_admission_failure version-false -v=false

printf 'SMB credential startup dispatch tests passed\n'
