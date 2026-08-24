#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'SMB credential admission checker test failed: %s\n' "$*" >&2
  exit 1
}

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
checker="$repo_root/deploy/systemd/check-smb-credential-admission.sh"
work_root="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-smb-admission-check.XXXXXX")"
trap 'rm -rf -- "$work_root"' EXIT

new_fixture() {
  local name=$1
  local fixture="$work_root/$name"
  install -d \
    "$fixture/build/sysroot/usr/lib/systemd/system" \
    "$fixture/build/sysroot/usr/share/recasaos/systemd/casaos.service.d"
  cp -- "$repo_root/build/sysroot/usr/lib/systemd/system/casaos.service" \
    "$fixture/build/sysroot/usr/lib/systemd/system/casaos.service"
  cp -- "$repo_root/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf" \
    "$fixture/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf"
  printf '%s\n' "$fixture"
}

expect_rejected() {
  local fixture=$1
  if "$checker" "$fixture" >/dev/null 2>&1; then
    fail "unsafe fixture was accepted: $fixture"
  fi
}

valid_fixture="$(new_fixture valid)"
"$checker" "$valid_fixture" >/dev/null

valid_static_hardening="$(new_fixture valid-static-hardening)"
install -d \
  "$valid_static_hardening/build/sysroot/etc/systemd/system/service.d" \
  "$valid_static_hardening/build/sysroot/usr/lib/systemd/system.conf.d" \
  "$valid_static_hardening/build/sysroot/usr/lib/systemd/system-generators"
printf '%s\n' '[Manager]' 'DefaultTimeoutStartSec=90s' > \
  "$valid_static_hardening/build/sysroot/usr/lib/systemd/system.conf.d/20-timeout.conf"
"$checker" "$valid_static_hardening" >/dev/null

base_active="$(new_fixture base-active)"
printf '%s\n' 'LoadCredential=recasaos-smb-keyring:/etc/recasaos/recasaos-smb-keyring' >> \
  "$base_active/build/sysroot/usr/lib/systemd/system/casaos.service"
expect_rejected "$base_active"

base_drift="$(new_fixture base-drift)"
printf '%s\n' 'TimeoutStopSec=30' >> \
  "$base_drift/build/sysroot/usr/lib/systemd/system/casaos.service"
expect_rejected "$base_drift"

set_credential="$(new_fixture set-credential)"
printf '%s\n' 'SetCredential=recasaos-smb-keyring:forbidden' >> \
  "$set_credential/build/sysroot/usr/lib/systemd/system/casaos.service"
expect_rejected "$set_credential"

import_credential="$(new_fixture import-credential)"
printf '%s\n' 'ImportCredential=recasaos-smb-*' >> \
  "$import_credential/build/sysroot/usr/lib/systemd/system/casaos.service"
expect_rejected "$import_credential"

injected_directory="$(new_fixture injected-directory)"
printf '%s\n' 'Environment=CREDENTIALS_DIRECTORY=/tmp/forbidden' >> \
  "$injected_directory/build/sysroot/usr/lib/systemd/system/casaos.service"
expect_rejected "$injected_directory"

wrong_source="$(new_fixture wrong-source)"
sed -i.bak 's#/etc/recasaos/recasaos-smb-keyring#/tmp/untrusted-keyring#' \
  "$wrong_source/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf"
expect_rejected "$wrong_source"

extra_directive="$(new_fixture extra-directive)"
printf '%s\n' 'Environment=RECASAOS_SMB_KEY=forbidden' >> \
  "$extra_directive/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf"
expect_rejected "$extra_directive"

packaged_active="$(new_fixture packaged-active)"
install -d "$packaged_active/build/sysroot/etc/systemd/system/casaos.service.d"
cp -- "$packaged_active/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf" \
  "$packaged_active/build/sysroot/etc/systemd/system/casaos.service.d/60-unexpected-name.conf"
expect_rejected "$packaged_active"

benign_active_dropin="$(new_fixture benign-active-dropin)"
install -d "$benign_active_dropin/build/sysroot/etc/systemd/system/casaos.service.d"
printf '%s\n' '[Service]' 'TimeoutStopSec=30' > \
  "$benign_active_dropin/build/sysroot/etc/systemd/system/casaos.service.d/40-benign.conf"
expect_rejected "$benign_active_dropin"

global_service_dropin="$(new_fixture global-service-dropin)"
install -d "$global_service_dropin/build/sysroot/etc/systemd/system/service.d"
printf '%s\n' '[Service]' \
  'LoadCredential=recasaos-smb-keyring:/etc/recasaos/recasaos-smb-keyring' > \
  "$global_service_dropin/build/sysroot/etc/systemd/system/service.d/99-global.conf"
expect_rejected "$global_service_dropin"

global_service_hardening="$(new_fixture global-service-hardening)"
install -d "$global_service_hardening/build/sysroot/etc/systemd/system/service.d"
printf '%s\n' '[Service]' 'NoNewPrivileges=yes' > \
  "$global_service_hardening/build/sysroot/etc/systemd/system/service.d/20-hardening.conf"
expect_rejected "$global_service_hardening"

alternate_root="$(new_fixture alternate-root)"
install -d "$alternate_root/build/sysroot/run/systemd/system"
printf '%s\n' '[Service]' \
  'LoadCredential=recasaos-smb-keyring:/etc/recasaos/recasaos-smb-keyring' > \
  "$alternate_root/build/sysroot/run/systemd/system/casaos.service"
expect_rejected "$alternate_root"

alternate_unit="$(new_fixture alternate-unit)"
install -d "$alternate_unit/build/sysroot/run/systemd/system"
printf '%s\n' '[Service]' 'ExecStart=/usr/bin/casaos' > \
  "$alternate_unit/build/sysroot/run/systemd/system/casaos.service"
expect_rejected "$alternate_unit"

indirect_environment="$(new_fixture indirect-environment)"
install -d "$indirect_environment/build/sysroot/etc/systemd/system/service.d"
printf '%s\n' '[Service]' 'EnvironmentFile=/etc/default/casaos' > \
  "$indirect_environment/build/sysroot/etc/systemd/system/service.d/50-environment.conf"
expect_rejected "$indirect_environment"

manager_environment="$(new_fixture manager-environment)"
install -d "$manager_environment/build/sysroot/usr/lib/systemd/system.conf.d"
printf '%s\n' '[Manager]' \
  'DefaultEnvironment=CREDENTIALS_DIRECTORY=/tmp/forbidden' > \
  "$manager_environment/build/sysroot/usr/lib/systemd/system.conf.d/60-credential.conf"
expect_rejected "$manager_environment"

system_generator="$(new_fixture system-generator)"
install -d "$system_generator/build/sysroot/usr/lib/systemd/system-generators"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > \
  "$system_generator/build/sysroot/usr/lib/systemd/system-generators/recasaos-generator"
chmod 0755 "$system_generator/build/sysroot/usr/lib/systemd/system-generators/recasaos-generator"
expect_rejected "$system_generator"

environment_generator="$(new_fixture environment-generator)"
install -d "$environment_generator/build/sysroot/etc/systemd/system-environment-generators"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' > \
  "$environment_generator/build/sysroot/etc/systemd/system-environment-generators/50-recasaos"
chmod 0755 "$environment_generator/build/sysroot/etc/systemd/system-environment-generators/50-recasaos"
expect_rejected "$environment_generator"

symlinked_directory="$(new_fixture symlinked-directory)"
install -d \
  "$symlinked_directory/build/sysroot/etc/systemd/system" \
  "$symlinked_directory/redirected-dropins"
ln -s "$symlinked_directory/redirected-dropins" \
  "$symlinked_directory/build/sysroot/etc/systemd/system/casaos.service.d"
expect_rejected "$symlinked_directory"

symlinked_staged_parent="$(new_fixture symlinked-staged-parent)"
mv "$symlinked_staged_parent/build/sysroot/usr/share/recasaos" \
  "$symlinked_staged_parent/redirected-recasaos"
ln -s "$symlinked_staged_parent/redirected-recasaos" \
  "$symlinked_staged_parent/build/sysroot/usr/share/recasaos"
expect_rejected "$symlinked_staged_parent"

symlinked_active_root="$(new_fixture symlinked-active-root)"
install -d \
  "$symlinked_active_root/build/sysroot/etc/systemd" \
  "$symlinked_active_root/redirected-system-root"
ln -s "$symlinked_active_root/redirected-system-root" \
  "$symlinked_active_root/build/sysroot/etc/systemd/system"
expect_rejected "$symlinked_active_root"

special_dropin="$(new_fixture special-dropin)"
install -d "$special_dropin/build/sysroot/etc/systemd/system/casaos.service.d"
mkfifo "$special_dropin/build/sysroot/etc/systemd/system/casaos.service.d/70-special.conf"
expect_rejected "$special_dropin"

missing="$(new_fixture missing)"
rm -- "$missing/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf"
expect_rejected "$missing"

printf 'SMB credential admission checker negative tests passed\n'
