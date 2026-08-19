#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files browser diagnostics policy failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
[[ $# -le 1 ]] || fail 'usage: check-public-files-browser-diagnostics-policy.sh [WORKFLOW]'
workflow="${1:-$repository/.github/workflows/recasaos-ci-security.yml}"
diagnostics="$repository/browser-tests/tests/navigation-diagnostics.js"
playwright="$repository/browser-tests/playwright.config.js"
public_files_spec="$repository/browser-tests/tests/public-files.spec.js"
validator="$repository/.github/scripts/validate-public-files-browser-diagnostics.sh"

for file in \
  "$workflow" \
  "$diagnostics" \
  "$playwright" \
  "$public_files_spec" \
  "$validator"
do
  [[ -f "$file" && ! -L "$file" ]] ||
    fail "required policy file is missing or linked"
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

command -v ruby >/dev/null 2>&1 || fail "Ruby YAML parser is unavailable"
ruby - "$workflow" <<'RUBY' || exit 1
require "yaml"
require "json"
require "digest"

def reject(reason)
  warn "public-files browser diagnostics policy failed: #{reason}"
  exit 1
end

workflow = YAML.safe_load(
  File.read(ARGV.fetch(0), encoding: "UTF-8"),
  permitted_classes: [],
  permitted_symbols: [],
  aliases: false,
)
reject("workflow root is not a mapping") unless workflow.is_a?(Hash)
reject("workflow root defaults are forbidden") if workflow.key?("defaults")
reject("workflow root environment changed") unless
  workflow["env"] == {"GOTOOLCHAIN" => "local"}
jobs = workflow["jobs"]
reject("workflow jobs are missing") unless jobs.is_a?(Hash)
test_job = jobs["test-and-vet"]
reject("test-and-vet job is missing") unless test_job.is_a?(Hash)
test_steps = test_job["steps"]
reject("test-and-vet steps are missing") unless test_steps.is_a?(Array)
policy_steps = {
  "Verify browser diagnostic retention policy" =>
    "bash .github/scripts/check-public-files-browser-diagnostics-policy.sh",
  "Exercise browser diagnostic policy negative cases" =>
    "bash .github/scripts/test-public-files-browser-diagnostics-policy.sh",
}
policy_steps.each do |name, command|
  matches = test_steps.select do |step|
    step.is_a?(Hash) && step["name"] == name
  end
  reject("policy step count for #{name} is #{matches.length}, want 1") unless
    matches.length == 1
  step = matches.fetch(0)
  reject("policy step has unexpected keys: #{name}") unless
    step.keys.sort == ["name", "run", "shell"]
  reject("policy step shell changed: #{name}") unless step["shell"] == "bash"
  reject("policy step command changed: #{name}") unless step["run"] == command
end
matching_job_ids = jobs.each_with_object([]) do |(job_id, candidate), result|
  if candidate.is_a?(Hash) &&
      candidate["name"] == "Public-files HTTPS browser smoke (Playwright)"
    result << job_id
  end
end
reject("browser job display name is not globally unique") unless
  matching_job_ids == ["public-files-browser-smoke"]
job = jobs["public-files-browser-smoke"]
reject("browser job is missing") unless job.is_a?(Hash)
canonicalize = lambda do |value|
  case value
  when Hash
    value.keys.sort.each_with_object({}) do |key, result|
      result[key] = canonicalize.call(value[key])
    end
  when Array
    value.map { |item| canonicalize.call(item) }
  else
    value
  end
end
job_digest = Digest::SHA256.hexdigest(JSON.generate(canonicalize.call(job)))
expected_job_digest = "cff2a06f51ec029ff0b72057f610083189ae5ffb31f763bb90c296fb59bb69e2"
reject("browser job semantic digest changed") unless
  job_digest == expected_job_digest
reject("browser job has unexpected keys") unless
  job.keys.sort == ["name", "runs-on", "steps", "timeout-minutes"]
reject("browser job name changed") unless
  job["name"] == "Public-files HTTPS browser smoke (Playwright)"
reject("browser runner changed") unless job["runs-on"] == "ubuntu-24.04"
reject("browser job timeout is not 40 minutes") unless
  job["timeout-minutes"] == 40

steps = job["steps"]
reject("browser steps are missing") unless steps.is_a?(Array)
expected_step_names = [
  "Check out source",
  "Set up Go 1.26.6",
  "Set up Node.js 24.18.0",
  "Install exact browser-test dependencies",
  "Install ephemeral browser dependencies",
  "Exercise browser diagnostic validator negative cases",
  "Exercise the HTTPS browser boundary",
  "Validate credential-safe browser failure diagnostics",
  "Upload credential-safe browser failure diagnostics",
]
actual_step_names = steps.map do |step|
  reject("browser step is not a mapping") unless step.is_a?(Hash)
  step["name"]
end
reject("browser step set or order changed") unless
  actual_step_names == expected_step_names

find_step = lambda do |name|
  matches = steps.select { |step| step.is_a?(Hash) && step["name"] == name }
  reject("browser step count for #{name} is #{matches.length}, want 1") unless
    matches.length == 1
  matches.fetch(0)
end

install = find_step.call("Install ephemeral browser dependencies")
reject("browser dependency step has unexpected keys") unless
  install.keys.sort == ["name", "run", "shell", "timeout-minutes"]
reject("browser dependency timeout is not 20 minutes") unless
  install["timeout-minutes"] == 20
reject("browser dependency shell changed") unless install["shell"] == "bash"
run = install["run"]
reject("browser dependency command is missing") unless run.is_a?(String)
lines = run.lines.map(&:chomp)
expected_prefix = [
  "browser-tests/node_modules/.bin/playwright install \\",
  "  --with-deps \\",
  "  chromium \\",
  "  firefox \\",
  "  webkit",
]
reject("Playwright install command or browser matrix changed") unless
  lines.first(expected_prefix.length) == expected_prefix
reject("browser job repeats apt metadata download") if
  lines.any? { |line| line.include?("apt-get update") }

boundary = find_step.call("Exercise the HTTPS browser boundary")
reject("browser boundary step has unexpected keys") unless
  boundary.keys.sort == ["env", "name", "run", "shell", "timeout-minutes"]
reject("browser boundary timeout is not 15 minutes") unless
  boundary["timeout-minutes"] == 15
reject("browser boundary shell changed") unless boundary["shell"] == "bash"
reject("browser boundary command changed") unless
  boundary["run"] == ".github/scripts/test-public-files-browser.sh"
RUBY

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
[[ "$(grep -Fc -- 'page.goto(' "$diagnostics")" == 1 ]] ||
  fail "diagnostic navigation must make exactly one attempt"
forbid_text "$diagnostics" 'page.reload(' \
  "diagnostic navigation must not reload"
for lifecycle_proof in \
  "browserName === 'firefox'" \
  "navigationError?.name === 'TimeoutError'" \
  'request.frame() === page.mainFrame()' \
  'navigationResponse?.from_service_worker === false' \
  "navigationResponse.method === 'GET'" \
  'navigationResponse.redirected === false' \
  "navigationResponse.resource_type === 'document'" \
  'navigationResponse?.status === 200' \
  'navigationResponse.url === portalOrigin' \
  'serverDelta?.started === 1' \
  'serverDelta.completed === 1' \
  'afterNavigationServer?.ok === true' \
  'afterNavigationServer.value?.active_requests === 0' \
  'afterNavigationServer.value.server_errors === 0' \
  'afterNavigationServer.value.tls_handshake_errors === 0' \
  'tlsProbe?.ok === true' \
  'tlsProbe.value?.ok === true' \
  'tlsProbe.value.status === 200' \
  'tlsProbe.value.tls?.authorized === true' \
  "tlsProbe.value.tls.protocol === 'TLSv1.3'" \
  'exactPreAuthorizationPage(firstPageState, portalOrigin, false)' \
  'exactPreAuthorizationPage(targetPageState, portalOrigin, true)' \
  'value.driver_url_is_about_blank === true' \
  'exactPortalURL(value.document_url, portalOrigin)' \
  'value.browser_hidden === true' \
  'value.controlled === false' \
  "value.document_ready_state === 'complete'" \
  'value.login_visible === true' \
  'value.secure_context === true' \
  'value.service_worker_registration_scopes.length === 0' \
  'value.token_empty === true'
do
  require_text "$diagnostics" "$lifecycle_proof" \
    "Firefox lifecycle proof is missing: $lifecycle_proof"
done
[[ "$(grep -Fc -- 'verifiedFirefoxDocumentState: false' "$diagnostics")" == 1 ]] ||
  fail "ordinary navigation must have exactly one false reconciliation marker"
[[ "$(grep -Fc -- 'verifiedFirefoxDocumentState: true' "$diagnostics")" == 1 ]] ||
  fail "Firefox reconciliation must have exactly one true marker"
require_text "$diagnostics" 'reconciliation_recheck: reconciliationRecheck' \
  "final pre-authorization recheck is not retained in failure diagnostics"
require_text "$diagnostics" \
  'validating the loaded document directly before continuing with ' \
  "Firefox reconciliation does not announce its direct-document boundary"
require_text "$public_files_spec" \
  'async function readReconciledPortalState(page)' \
  "direct reconciled DOM assertion is missing"
require_text "$public_files_spec" \
  'if (navigation.verifiedFirefoxDocumentState === true)' \
  "Firefox reconciliation is not isolated from locator auto-wait"
require_text "$public_files_spec" \
  "'reconciled Firefox portal state must remain pre-authorization'" \
  "Firefox reconciled DOM postcondition is missing"
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
