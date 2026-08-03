#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files browser diagnostics validator test failed: %s\n' "$*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == true ]] || fail "not running in GitHub Actions"
[[ "${GITHUB_REPOSITORY:-}" == "EdmundFu-233/ReCasaOS" ]] ||
  fail "repository identity changed"
[[ "${RUNNER_OS:-}" == Linux ]] || fail "runner is not Linux"
[[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted ]] ||
  fail "runner is not GitHub-hosted"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] || fail "run id is unsafe"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] ||
  fail "run attempt is unsafe"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] ||
  fail "RUNNER_TEMP is unsafe"

runner_temp="$(realpath -e -- "$RUNNER_TEMP")"
[[ "$runner_temp" == /home/runner/work/_temp ]] ||
  fail "RUNNER_TEMP is not the exact hosted-runner path"
test_key="${GITHUB_RUN_ID}9-${GITHUB_RUN_ATTEMPT}9"
directory="${runner_temp}/recasaos-browser-diagnostics-${test_key}"
json="${directory}/firefox-0123456789ab-diagnostics.json"
symlink="${directory}/firefox-0123456789ab-trace.zip"
validator=".github/scripts/validate-public-files-browser-diagnostics.sh"

case "$directory" in
  /home/runner/work/_temp/recasaos-browser-diagnostics-[0-9]*-[0-9]*) ;;
  *) fail "test directory is outside its safe root" ;;
esac
[[ ! -e "$directory" && ! -L "$directory" ]] ||
  fail "test directory already exists"

cleanup() {
  local status=$?
  trap - EXIT
  case "$directory" in
    /home/runner/work/_temp/recasaos-browser-diagnostics-[0-9]*-[0-9]*)
      rm -rf -- "$directory"
      ;;
    *)
      exit 1
      ;;
  esac
  exit "$status"
}
trap cleanup EXIT

install -d -m 0700 "$directory"
umask 077

write_safe_json() {
  printf '%s\n' \
    '{"browser":{},"github":{},"navigation":{},"pages":{},"schema":"recasaos-browser-navigation-diagnostics-v1","service":{},"trace":{"preserved":false},"trace_start_error":null}' \
    >"$json"
  chmod 0600 "$json"
}

write_safe_json
bash "$validator" "$directory" >/dev/null

printf '%s\n' \
  '{"browser":{"name":"rc1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},"github":{},"navigation":{},"pages":{},"schema":"recasaos-browser-navigation-diagnostics-v1","service":{},"trace":{"preserved":false},"trace_start_error":null}' \
  >"$json"
chmod 0600 "$json"
if bash "$validator" "$directory" >/dev/null 2>&1; then
  fail "validator accepted a bearer-like value"
fi

write_safe_json
ln -s -- "$json" "$symlink"
if bash "$validator" "$directory" >/dev/null 2>&1; then
  fail "validator accepted a symlink"
fi
rm -- "$symlink"

bash "$validator" "$directory" >/dev/null
