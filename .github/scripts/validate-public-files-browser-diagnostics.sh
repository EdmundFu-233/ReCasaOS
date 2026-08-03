#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files browser diagnostics rejected: %s\n' "$*" >&2
  exit 1
}

[[ "$#" == 1 ]] || fail "expected one diagnostics directory"
[[ "${GITHUB_ACTIONS:-}" == true ]] ||
  fail "validation is restricted to GitHub Actions"
[[ "${GITHUB_REPOSITORY:-}" == "EdmundFu-233/ReCasaOS" ]] ||
  fail "the repository identity is not trusted"
[[ "${RUNNER_OS:-}" == Linux ]] || fail "the runner is not Linux"
[[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted ]] ||
  fail "the runner is not GitHub-hosted"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] ||
  fail "RUNNER_TEMP is missing or unsafe"

command -v node >/dev/null 2>&1 || fail "node is unavailable"
command -v unzip >/dev/null 2>&1 || fail "unzip is unavailable"
sensitive_trace_pattern='"name"[[:space:]]*:[[:space:]]*"(proxy-authorization|authorization|set-cookie|cookie)"|"(proxy-authorization|authorization|set-cookie|cookie)"[[:space:]]*:|"cookies"[[:space:]]*:[[:space:]]*\[[[:space:]]*\{'

runner_temp="$(realpath -e -- "$RUNNER_TEMP")"
[[ "$runner_temp" == /home/runner/work/_temp ]] ||
  fail "RUNNER_TEMP is not the exact hosted-runner path"

diagnostics_directory="$1"
case "$diagnostics_directory" in
  /home/runner/work/_temp/recasaos-browser-diagnostics-[0-9]*-[0-9]*) ;;
  *) fail "diagnostics directory is outside its allowlisted root" ;;
esac
[[ -d "$diagnostics_directory" && ! -L "$diagnostics_directory" ]] ||
  fail "diagnostics directory is missing or is a symlink"
[[ "$(realpath -e -- "$diagnostics_directory")" == "$diagnostics_directory" ]] ||
  fail "diagnostics directory is not canonical"
[[ "$(stat -c %u "$diagnostics_directory")" == "$(id -u)" ]] ||
  fail "diagnostics directory owner changed"
[[ "$(stat -c %a "$diagnostics_directory")" == 700 ]] ||
  fail "diagnostics directory mode changed"

mapfile -d '' entries < <(
  find "$diagnostics_directory" -mindepth 1 -maxdepth 1 -print0
)
(( "${#entries[@]}" > 0 )) || fail "no diagnostics were produced"
(( "${#entries[@]}" <= 6 )) || fail "too many diagnostic files"

diagnostics_count=0
for entry in "${entries[@]}"; do
  [[ -f "$entry" && ! -L "$entry" ]] ||
    fail "diagnostic entry is not a regular file"
  [[ "$(stat -c %u "$entry")" == "$(id -u)" ]] ||
    fail "diagnostic file owner changed"
  [[ "$(stat -c %a "$entry")" == 600 ]] ||
    fail "diagnostic file mode changed"
  [[ "$(stat -c %h "$entry")" == 1 ]] ||
    fail "diagnostic file has multiple links"

  name="$(basename -- "$entry")"
  [[ "$name" =~ ^(chromium|firefox|webkit)-[a-f0-9]{12}-(diagnostics\.json|trace\.zip)$ ]] ||
    fail "diagnostic filename is not allowlisted"
  if LC_ALL=C grep -aqE 'rc1_[A-Za-z0-9_-]{43}' "$entry"; then
    fail "diagnostic file contains a ReCasaOS bearer"
  fi
  if LC_ALL=C grep -aqEi "$sensitive_trace_pattern" "$entry"; then
    fail "diagnostic file contains credential metadata"
  fi

  size="$(stat -c %s "$entry")"
  case "$name" in
    *-diagnostics.json)
      (( size > 0 && size <= 1048576 )) ||
        fail "diagnostic JSON size is invalid"
      node -e '
        const fs = require("node:fs");
        const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
        const expected = [
          "browser", "github", "navigation", "pages", "schema", "service",
          "trace", "trace_start_error",
        ];
        const keys = Object.keys(value).sort();
        if (
          JSON.stringify(keys) !== JSON.stringify(expected) ||
          value.schema !== "recasaos-browser-navigation-diagnostics-v1" ||
          value.trace === null ||
          typeof value.trace !== "object" ||
          typeof value.trace.preserved !== "boolean"
        ) {
          process.exit(1);
        }
      ' "$entry" || fail "diagnostic JSON schema is invalid"
      diagnostics_count=$((diagnostics_count + 1))
      ;;
    *-trace.zip)
      (( size > 0 && size <= 33554432 )) ||
        fail "trace archive size is invalid"
      unzip -tqq "$entry" || fail "trace archive is corrupt"
      if unzip -p "$entry" |
        LC_ALL=C grep -aE 'rc1_[A-Za-z0-9_-]{43}' >/dev/null
      then
        fail "expanded trace contains a ReCasaOS bearer"
      fi
      if unzip -p "$entry" |
        LC_ALL=C grep -aEi "$sensitive_trace_pattern" >/dev/null
      then
        fail "expanded trace contains credential metadata"
      fi
      companion="${entry%-trace.zip}-diagnostics.json"
      [[ -f "$companion" && ! -L "$companion" ]] ||
        fail "trace archive has no diagnostic companion"
      ;;
  esac
done

(( diagnostics_count > 0 )) || fail "no diagnostic JSON was produced"

for entry in "${entries[@]}"; do
  case "$entry" in
    *-diagnostics.json)
      node -e '
        const fs = require("node:fs");
        const path = require("node:path");
        const value = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
        if (!value.trace.preserved) process.exit(0);
        const expected = path.basename(process.argv[1]).replace(
          /-diagnostics\.json$/,
          "-trace.zip",
        );
        if (value.trace.filename !== expected) process.exit(1);
      ' "$entry" || fail "diagnostic JSON references the wrong trace"
      ;;
  esac
done

printf 'validated %d credential-safe browser diagnostic bundle(s)\n' \
  "$diagnostics_count"
