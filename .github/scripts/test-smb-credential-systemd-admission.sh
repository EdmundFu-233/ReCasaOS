#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'SMB credential systemd admission test failed: %s\n' "$*" >&2
  exit 1
}

[[ "${RECASAOS_TRUSTED_SYSTEMD_CI:-0}" == 1 ]] || fail 'explicit trusted systemd opt-in is missing'
[[ "${RECASAOS_SYSTEMD_TEST_TARGET:-}" == debian-11-systemd-247-qemu ]] ||
  fail 'test is not running in the reviewed Debian 11 VM target'
[[ "$(cat /proc/1/comm)" == systemd ]] || fail 'systemd is not PID 1'
systemd_version="$(systemd-analyze --version | awk 'NR == 1 { print $2 }')"
[[ "$systemd_version" == 247 ]] || fail 'systemd version is not 247'

repo_root="$(cd -- "${GITHUB_WORKSPACE:?GITHUB_WORKSPACE is missing}" && pwd -P)"
staged_dropin="$repo_root/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf"
[[ -f "$staged_dropin" && ! -L "$staged_dropin" ]] || fail 'staged drop-in is unavailable'
staged_directives="$(
  sed -e 's/[[:space:]]*$//' \
    -e '/^[[:space:]]*[#;]/d' \
    -e '/^[[:space:]]*$/d' \
    "$staged_dropin"
)"
expected_staged_directives=$'[Service]\nLoadCredential=recasaos-smb-keyring:/etc/recasaos/recasaos-smb-keyring'
[[ "$staged_directives" == "$expected_staged_directives" ]] ||
  fail 'staged drop-in drifted from the reviewed credential binding'

unit_name=recasaos-smb-admission-test.service
unit_path="/etc/systemd/system/$unit_name"
dropin_directory="/etc/systemd/system/$unit_name.d"
dropin_path="$dropin_directory/50-recasaos-smb-credential.conf"
result_path=/run/recasaos-smb-admission-test.result
source_directory=/etc/recasaos
source_path=/etc/recasaos/recasaos-smb-keyring

for unit_root in \
  /etc/systemd/system \
  /run/systemd/system \
  /usr/local/lib/systemd/system \
  /usr/lib/systemd/system \
  /lib/systemd/system
do
  candidate="$unit_root/$unit_name"
  [[ ! -e "$candidate" && ! -L "$candidate" &&
    ! -e "$candidate.d" && ! -L "$candidate.d" ]] ||
    fail "test unit namespace is already occupied: $candidate"
done
for target in "$unit_path" "$dropin_path" "$result_path" "$source_path"; do
  [[ ! -e "$target" && ! -L "$target" ]] ||
    fail "refusing to replace pre-existing test target: $target"
done
for directory in "$dropin_directory" "$source_directory"; do
  if [[ -e "$directory" || -L "$directory" ]]; then
    [[ -d "$directory" && ! -L "$directory" ]] ||
      fail "unsafe pre-existing test directory: $directory"
  fi
done
if systemctl cat "$unit_name" >/dev/null 2>&1; then
  fail "a test unit is already installed: $unit_name"
fi
unit_load_state="$(systemctl show --property=LoadState --value "$unit_name" 2>/dev/null)" ||
  fail "could not inspect the test unit load state: $unit_name"
[[ "$unit_load_state" == not-found ]] ||
  fail "a test unit is already known to systemd: $unit_name"

work_root="$(mktemp -d /tmp/recasaos-smb-systemd-admission.XXXXXX)"
case "$work_root" in
  /tmp/recasaos-smb-systemd-admission.[A-Za-z0-9]*) ;;
  *) fail "unsafe test workspace: $work_root" ;;
esac
helper_source="$work_root/main.go"
helper_binary="$work_root/admission-helper"
unit_source="$work_root/recasaos-smb-admission-test.service"
journal_output="$work_root/unit.journal"

owned_unit_path=0
owned_dropin_path=0
owned_result_path=0
owned_source_path=0
created_dropin_directory=0
created_source_directory=0

cleanup() {
  status=$?
  trap - EXIT
  set +e
  if [[ "$owned_unit_path" == 1 ]]; then
    sudo systemctl stop "$unit_name" >/dev/null 2>&1 || true
  fi
  [[ "$owned_unit_path" == 0 ]] || sudo rm -f -- "$unit_path"
  [[ "$owned_dropin_path" == 0 ]] || sudo rm -f -- "$dropin_path"
  [[ "$owned_result_path" == 0 ]] || sudo rm -f -- "$result_path"
  [[ "$owned_source_path" == 0 ]] || sudo rm -f -- "$source_path"
  [[ "$created_dropin_directory" == 0 ]] || sudo rmdir -- "$dropin_directory" 2>/dev/null || true
  [[ "$created_source_directory" == 0 ]] || sudo rmdir -- "$source_directory" 2>/dev/null || true
  if [[ "$owned_unit_path" == 1 || "$owned_dropin_path" == 1 ]]; then
    sudo systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  case "$work_root" in
    /tmp/recasaos-smb-systemd-admission.[A-Za-z0-9]*) rm -rf -- "$work_root" ;;
  esac
  exit "$status"
}
trap cleanup EXIT

cat >"$helper_source" <<'GO'
package main

import (
	"fmt"
	"os"

	"github.com/IceWhaleTech/CasaOS/pkg/smbcredentials"
)

func fail() {
	fmt.Fprintln(os.Stderr, "ReCasaOS SMB runtime credential admission failed")
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		fail()
	}
	switch os.Args[1] {
	case "provision":
		result, err := smbcredentials.ProvisionSystemKeyringSource()
		if err != nil || !result.Created || result.DurabilityUnknown || result.CleanupRequired {
			fail()
		}
	case "malformed":
		if err := os.WriteFile(smbcredentials.SourceKeyringPath, []byte("malformed-systemd-credential-sentinel"), 0o400); err != nil {
			fail()
		}
	case "admit":
		if len(os.Args) != 3 {
			fail()
		}
		keyring, err := smbcredentials.LoadSystemdKeyring()
		if keyring != nil {
			defer keyring.Destroy()
		}
		result := "validated\n"
		if keyring == nil && err == smbcredentials.ErrSystemdCredentialNotProvided {
			result = "legacy\n"
		} else if err != nil || keyring == nil {
			fail()
		}
		if err := os.WriteFile(os.Args[2], []byte(result), 0o600); err != nil {
			fail()
		}
	default:
		fail()
	}
}
GO

(
  cd -- "$repo_root"
  go build -trimpath -o "$helper_binary" "$helper_source"
)

cat >"$unit_source" <<EOF
[Unit]
Description=ReCasaOS SMB credential admission integration test

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$helper_binary admit $result_path
EOF
if [[ ! -d "$source_directory" ]]; then
  sudo install -d -o root -g root -m 0700 "$source_directory"
  created_source_directory=1
fi
sudo install -o root -g root -m 0644 "$unit_source" "$unit_path"
owned_unit_path=1
sudo systemctl daemon-reload

sudo systemctl start "$unit_name"
owned_result_path=1
[[ "$(sudo cat "$result_path")" == legacy ]] || fail 'unconfigured unit did not take the legacy admission path'

if [[ ! -d "$dropin_directory" ]]; then
  sudo install -d -o root -g root -m 0755 "$dropin_directory"
  created_dropin_directory=1
fi
sudo install -o root -g root -m 0644 "$staged_dropin" "$dropin_path"
owned_dropin_path=1
sudo systemctl daemon-reload
sudo rm -f -- "$result_path"
sudo systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
if sudo systemctl restart "$unit_name" >/dev/null 2>&1; then
  fail 'missing configured source unexpectedly started'
fi
[[ ! -e "$result_path" ]] || fail 'helper ran despite missing LoadCredential source'

sudo "$helper_binary" provision
owned_source_path=1
sudo systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
sudo rm -f -- "$result_path"
sudo systemctl start "$unit_name"
[[ "$(sudo cat "$result_path")" == validated ]] || fail 'valid systemd credential was not admitted'

sudo systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
sudo rm -f -- "$result_path"
sudo systemctl restart "$unit_name"
[[ "$(sudo cat "$result_path")" == validated ]] || fail 'valid credential restart was not admitted'

sudo rm -f -- "$result_path" "$source_path"
sudo "$helper_binary" malformed
sudo systemctl reset-failed "$unit_name" >/dev/null 2>&1 || true
if sudo systemctl restart "$unit_name" >/dev/null 2>&1; then
  fail 'malformed configured credential unexpectedly started'
fi
[[ ! -e "$result_path" ]] || fail 'malformed credential produced a success marker'
malformed_invocation_id="$(
  sudo systemctl show --property=InvocationID --value "$unit_name"
)" || fail 'could not inspect the malformed credential invocation'
[[ "$malformed_invocation_id" =~ ^[0-9a-f]{32}$ ]] ||
  fail 'malformed credential invocation ID is unavailable'
if ! sudo journalctl --no-pager \
  "_SYSTEMD_INVOCATION_ID=$malformed_invocation_id" >"$journal_output"; then
  fail 'could not read the SMB admission test journal'
fi
grep -Fq 'ReCasaOS SMB runtime credential admission failed' "$journal_output" ||
  fail 'malformed credential failure was absent from the journal'
if grep -Fq 'malformed-systemd-credential-sentinel' "$journal_output"; then
  fail 'malformed credential bytes appeared in the journal'
fi

printf 'SMB credential systemd 247 admission tests passed\n'
