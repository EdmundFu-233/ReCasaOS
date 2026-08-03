#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files browser diagnostics policy failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
workflow="$repository/.github/workflows/recasaos-ci-security.yml"
diagnostics="$repository/browser-tests/tests/navigation-diagnostics.js"
playwright="$repository/browser-tests/playwright.config.js"
validator="$repository/.github/scripts/validate-public-files-browser-diagnostics.sh"

for file in "$workflow" "$diagnostics" "$playwright" "$validator"; do
  [[ -f "$file" ]] || fail "required policy file is missing"
done

require_text() {
  local file="$1"
  local value="$2"
  local reason="$3"
  grep -Fq -- "$value" "$file" || fail "$reason"
}

forbid_text() {
  local file="$1"
  local value="$2"
  local reason="$3"
  if grep -Fq -- "$value" "$file"; then
    fail "$reason"
  fi
}

[[ "$(grep -Fc -- 'uses: actions/upload-artifact@' "$workflow")" == 1 ]] ||
  fail "workflow must contain exactly one artifact uploader"
require_text "$workflow" \
  'uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1' \
  "artifact uploader is not pinned to the reviewed commit"
require_text "$workflow" \
  'steps.browser-diagnostics.outputs.ready == '\''true'\''' \
  "upload is not gated by successful diagnostic validation"
require_text "$workflow" \
  'github.event.pull_request.head.repo.full_name == github.repository' \
  "fork uploads are not excluded"
for association in OWNER MEMBER COLLABORATOR; do
  require_text "$workflow" \
    "github.event.pull_request.author_association == '$association'" \
    "trusted author association is missing: $association"
done
require_text "$workflow" \
  'path: ${{ runner.temp }}/recasaos-browser-diagnostics-${{ github.run_id }}-${{ github.run_attempt }}' \
  "artifact path is not exact"
require_text "$workflow" 'if-no-files-found: error' \
  "missing diagnostics do not fail closed"
require_text "$workflow" 'retention-days: 1' \
  "diagnostic retention is not one day"
require_text "$workflow" 'include-hidden-files: false' \
  "hidden diagnostic files are not excluded"
require_text "$workflow" \
  'bash .github/scripts/validate-public-files-browser-diagnostics.sh' \
  "independent diagnostic validation is not invoked"

require_text "$diagnostics" \
  'const bearerPattern = /rc1_[A-Za-z0-9_-]{43}/;' \
  "in-process bearer scanner is missing"
require_text "$diagnostics" 'const sensitiveTraceDataPattern =' \
  "in-process credential-metadata scanner is missing"
for credential_scan_target in archive stdout serialized; do
  require_text "$diagnostics" \
    "diagnosticBytesContainSensitiveTraceData($credential_scan_target)" \
    "in-process credential-metadata scan is missing: $credential_scan_target"
done
require_text "$diagnostics" 'const navigationTimeoutMs = 20_000;' \
  "bounded navigation deadline changed"
require_text "$diagnostics" 'sources: false' \
  "trace source capture is not disabled"
require_text "$diagnostics" \
  'refusing to trace outside the pre-authorization boundary' \
  "pre-authorization trace guard is missing"
require_text "$validator" \
  "grep -aqE 'rc1_[A-Za-z0-9_-]{43}'" \
  "independent raw-file bearer scan is missing"
require_text "$validator" \
  "grep -aE 'rc1_[A-Za-z0-9_-]{43}'" \
  "independent expanded-trace bearer scan is missing"
require_text "$validator" 'sensitive_trace_pattern=' \
  "independent credential-metadata scanner is missing"
require_text "$validator" 'grep -aqEi "$sensitive_trace_pattern"' \
  "independent raw credential-metadata scan is missing"
require_text "$validator" 'grep -aEi "$sensitive_trace_pattern"' \
  "independent expanded credential-metadata scan is missing"

require_text "$playwright" "preserveOutput: 'never'" \
  "ordinary Playwright output retention changed"
require_text "$playwright" "trace: 'off'" \
  "global trace capture must stay disabled"
require_text "$playwright" "video: 'off'" \
  "video capture must stay disabled"
forbid_text "$workflow" 'actions/download-artifact' \
  "primary CI must not consume diagnostic artifacts"
