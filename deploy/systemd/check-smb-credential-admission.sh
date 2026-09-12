#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'SMB credential admission check failed: %s\n' "$*" >&2
  exit 1
}

repo_root=${1:-.}
repo_root="$(cd -- "$repo_root" && pwd -P)"
base_unit="$repo_root/build/sysroot/usr/lib/systemd/system/casaos.service"
staged_dropin="$repo_root/build/sysroot/usr/share/recasaos/systemd/casaos.service.d/50-recasaos-smb-credential.conf"

require_physical_directory_chain() {
  local directory=$1
  local relative
  local current=$repo_root
  local component
  local -a components=()

  [[ "$directory" == "$repo_root" || "$directory" == "$repo_root/"* ]] ||
    fail "directory escapes the repository boundary: $directory"
  [[ "$directory" != "$repo_root" ]] || return 0
  relative=${directory#"$repo_root"/}
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    [[ -n "$component" && "$component" != . && "$component" != .. ]] ||
      fail "directory has a noncanonical component: $directory"
    current="$current/$component"
    if [[ -e "$current" || -L "$current" ]]; then
      [[ -d "$current" && ! -L "$current" ]] ||
        fail "packaged directory chain is unsafe: $current"
    else
      return 0
    fi
  done
}

require_physical_directory_chain "${base_unit%/*}"
require_physical_directory_chain "${staged_dropin%/*}"

[[ -f "$base_unit" && ! -L "$base_unit" && -r "$base_unit" ]] ||
  fail 'base casaos.service is missing or unsafe'
[[ -f "$staged_dropin" && ! -L "$staged_dropin" && -r "$staged_dropin" ]] ||
  fail 'staged credential drop-in is missing or unsafe'

contains_credential_configuration() {
  local file=$1
  local result

  result="$(awk '
    /^[[:space:]]*[#;]/ { next }
    /^[[:space:]]*(Load|Set|Import)Credential[A-Za-z]*[[:space:]]*=/ { found = 1 }
    /^[[:space:]]*(Environment|EnvironmentFile|PassEnvironment)[[:space:]]*=/ { found = 1 }
    /^[[:space:]]*(DefaultEnvironment|ManagerEnvironment)[[:space:]]*=/ { found = 1 }
    /CREDENTIALS_DIRECTORY/ { found = 1 }
    END { if (found) print "found" }
  ' "$file")" || fail "could not inspect packaged unit configuration: $file"
  [[ "$result" == found ]]
}

if contains_credential_configuration "$base_unit"; then
  fail 'base casaos.service must remain compatible with an unprovisioned legacy installation'
fi

base_directives="$(
  sed -e 's/[[:space:]]*$//' \
    -e '/^[[:space:]]*[#;]/d' \
    -e '/^[[:space:]]*$/d' \
    "$base_unit"
)"
expected_base_directives=$'[Unit]\nAfter=casaos-message-bus.service\nAfter=rclone.service\nDescription=CasaOS Main Service\n[Service]\nExecStart=/usr/bin/casaos -c /etc/casaos/casaos.conf\nPIDFile=/var/run/casaos/casaos.pid\nRestart=always\nType=notify\n[Install]\nWantedBy=multi-user.target'
[[ "$base_directives" == "$expected_base_directives" ]] ||
  fail 'base casaos.service drifted from the reviewed legacy-compatible unit'

directives="$(
  sed -e 's/[[:space:]]*$//' \
    -e '/^[[:space:]]*#/d' \
    -e '/^[[:space:]]*$/d' \
    "$staged_dropin"
)"
expected_directives=$'[Service]\nLoadCredential=recasaos-smb-keyring:/etc/recasaos/recasaos-smb-keyring'
[[ "$directives" == "$expected_directives" ]] ||
  fail 'staged drop-in does not contain only the fixed credential binding'

for active_root in \
  etc/systemd/system \
  run/systemd/system \
  usr/local/lib/systemd/system \
  usr/lib/systemd/system \
  lib/systemd/system
do
  require_physical_directory_chain "$repo_root/build/sysroot/$active_root"
  active_unit="$repo_root/build/sysroot/$active_root/casaos.service"
  if [[ -e "$active_unit" || -L "$active_unit" ]]; then
    [[ -f "$active_unit" && ! -L "$active_unit" && -r "$active_unit" ]] ||
      fail "active packaged unit is unsafe: $active_unit"
    [[ "$active_unit" == "$base_unit" ]] ||
      fail "alternate packaged casaos.service would override the reviewed base unit: $active_unit"
    if contains_credential_configuration "$active_unit"; then
      fail "credential directive is active in packaged unit: $active_unit"
    fi
  fi
  for active_directory in \
    "$repo_root/build/sysroot/$active_root/casaos.service.d" \
    "$repo_root/build/sysroot/$active_root/service.d"
  do
    if [[ -e "$active_directory" || -L "$active_directory" ]]; then
      [[ -d "$active_directory" && ! -L "$active_directory" &&
        -r "$active_directory" && -x "$active_directory" ]] ||
        fail "active packaged drop-in directory is unsafe: $active_directory"
    else
      continue
    fi
    shopt -s nullglob
    active_dropins=("$active_directory"/*.conf)
    shopt -u nullglob
    if [[ ${#active_dropins[@]} -ne 0 ]]; then
      fail "an active packaged drop-in can alter casaos.service: $active_directory"
    fi
    for active_dropin in "${active_dropins[@]}"; do
      [[ -f "$active_dropin" && ! -L "$active_dropin" && -r "$active_dropin" ]] ||
        fail "active packaged drop-in is unsafe: $active_dropin"
      if contains_credential_configuration "$active_dropin"; then
        fail "credential directive is active in packaged drop-in: $active_dropin"
      fi
    done
  done
done

for systemd_root in \
  etc/systemd \
  run/systemd \
  usr/local/lib/systemd \
  usr/lib/systemd \
  lib/systemd
do
  require_physical_directory_chain "$repo_root/build/sysroot/$systemd_root"
  manager_configuration="$repo_root/build/sysroot/$systemd_root/system.conf"
  if [[ -e "$manager_configuration" || -L "$manager_configuration" ]]; then
    [[ -f "$manager_configuration" && ! -L "$manager_configuration" &&
      -r "$manager_configuration" ]] ||
      fail "packaged system manager configuration is unsafe: $manager_configuration"
    if contains_credential_configuration "$manager_configuration"; then
      fail "packaged system manager configuration can inject a credential environment: $manager_configuration"
    fi
  fi

  manager_dropin_directory="$repo_root/build/sysroot/$systemd_root/system.conf.d"
  if [[ -e "$manager_dropin_directory" || -L "$manager_dropin_directory" ]]; then
    [[ -d "$manager_dropin_directory" && ! -L "$manager_dropin_directory" &&
      -r "$manager_dropin_directory" && -x "$manager_dropin_directory" ]] ||
      fail "packaged system manager drop-in directory is unsafe: $manager_dropin_directory"
    shopt -s nullglob
    manager_dropins=("$manager_dropin_directory"/*.conf)
    shopt -u nullglob
    for manager_dropin in "${manager_dropins[@]}"; do
      [[ -f "$manager_dropin" && ! -L "$manager_dropin" && -r "$manager_dropin" ]] ||
        fail "packaged system manager drop-in is unsafe: $manager_dropin"
      if contains_credential_configuration "$manager_dropin"; then
        fail "packaged system manager drop-in can inject a credential environment: $manager_dropin"
      fi
    done
  fi

  for generator_kind in system-generators system-environment-generators; do
    generator_directory="$repo_root/build/sysroot/$systemd_root/$generator_kind"
    if [[ -e "$generator_directory" || -L "$generator_directory" ]]; then
      [[ -d "$generator_directory" && ! -L "$generator_directory" &&
        -r "$generator_directory" && -x "$generator_directory" ]] ||
        fail "packaged systemd generator directory is unsafe: $generator_directory"
      shopt -s dotglob nullglob
      generators=("$generator_directory"/*)
      shopt -u dotglob nullglob
      [[ ${#generators[@]} -eq 0 ]] ||
        fail "packaged systemd generators can bypass the static credential boundary: $generator_directory"
    fi
  done
done

printf 'SMB credential admission boundary is staged and packaged-static legacy-compatible\n'
