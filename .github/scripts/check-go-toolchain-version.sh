#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Go toolchain version policy check failed: %s\n' "$*" >&2
  exit 1
}

expected=1.26.6
expected_language=1.25.0
script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="${1:-$(cd -- "$script_directory/../.." && pwd -P)}"
repository="$(cd -- "$repository" && pwd -P)"
go_module="$repository/go.mod"
workflow_checker="$script_directory/check-go-toolchain-workflows.py"
workflows=()
for workflow in \
  "$repository"/.github/workflows/*.yml \
  "$repository"/.github/workflows/*.yaml; do
  [[ -e "$workflow" ]] || continue
  workflows+=("$workflow")
done
runtime_scripts=(
  "$repository/.github/scripts/test-public-files-debian11-vm.sh"
  "$repository/.github/scripts/test-public-files-systemd.sh"
)
scanned_scripts=()
for script in "$repository"/.github/scripts/*; do
  [[ -f "$script" ]] || continue
  [[ "$(basename "$script")" == test-go-toolchain-version-policy.sh ]] &&
    continue
  scanned_scripts+=("$script")
done

[[ "${#workflows[@]}" -gt 0 ]] || fail 'no workflow files were found'
[[ "${#scanned_scripts[@]}" -gt 0 ]] || fail 'no policy scripts were found'
if find "$repository/.github/workflows" "$repository/.github/scripts" \
  -maxdepth 1 -type l -print -quit | grep -q .; then
  fail 'workflow or policy script symlink is forbidden'
fi

for file in "$go_module" "${workflows[@]}" "${scanned_scripts[@]}"; do
  [[ -f "$file" && ! -L "$file" ]] ||
    fail "required policy file is missing or symbolic: $file"
done
[[ -f "$workflow_checker" && ! -L "$workflow_checker" ]] ||
  fail 'workflow structure checker is missing or symbolic'

[[ "$(grep -Fxc -- "go $expected_language" "$go_module")" == 1 ]] ||
  fail "go.mod must pin exactly one language version $expected_language directive"
[[ "$(grep -Fxc -- "toolchain go$expected" "$go_module")" == 1 ]] ||
  fail "go.mod must pin exactly one toolchain go$expected directive"

command -v python3 >/dev/null 2>&1 || fail 'python3 is unavailable'
python3 "$workflow_checker" "$expected" "${workflows[@]}" ||
  fail 'workflow step structure is unsafe'

while IFS= read -r version; do
  case "$version" in
    "$expected"|"go$expected") ;;
    *) fail "stale or unreviewed Go toolchain pin found: $version" ;;
  esac
done < <(
  grep -hEo -- 'go1\.[0-9]+\.[0-9]+' \
    "${scanned_scripts[@]}" | sort -u
)

while IFS= read -r version; do
  [[ "$version" == "$expected" ]] ||
    fail "stale hosted-toolcache Go version found: $version"
done < <(
  grep -hEo -- '/opt/hostedtoolcache/go/[0-9]+\.[0-9]+\.[0-9]+' \
    "${scanned_scripts[@]}" | sed 's#.*/##' | sort -u
)

grep -Fq -- "go version go$expected linux/amd64" \
  "$repository/.github/scripts/test-public-files-debian11-vm.sh" ||
  fail 'Debian VM host/guest toolchain assertion drifted'
grep -Fq -- "/opt/hostedtoolcache/go/$expected/*" \
  "$repository/.github/scripts/test-public-files-debian11-vm.sh" ||
  fail 'Debian VM hosted-toolcache boundary drifted'
grep -Fq -- "go version go$expected linux/amd64" \
  "$repository/.github/scripts/test-public-files-systemd.sh" ||
  fail 'systemd integration toolchain assertion drifted'

printf 'Go toolchain version policy passed: language=%s toolchain=%s\n' \
  "$expected_language" "$expected"
