#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files browser diagnostics policy tests failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
checker="$script_directory/check-public-files-browser-diagnostics-policy.sh"
workflow="$repository/.github/workflows/recasaos-ci-security.yml"
workspace="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-browser-policy.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT

replace_once() {
  local file=$1
  local needle=$2
  local replacement=$3

  NEEDLE="$needle" REPLACEMENT="$replacement" perl -0pi -e '
    BEGIN {
      $needle = $ENV{"NEEDLE"};
      $replacement = $ENV{"REPLACEMENT"};
    }
    $offset = index($_, $needle);
    die "test mutation target is missing\n" if $offset < 0;
    substr($_, $offset, length($needle), $replacement);
  ' "$file"
}

expect_rejection() {
  local label=$1
  local needle=$2
  local replacement=$3
  local candidate="$workspace/$label.yml"

  cp -- "$workflow" "$candidate"
  replace_once "$candidate" "$needle" "$replacement"
  if "$checker" "$candidate" >"$workspace/$label.log" 2>&1; then
    fail "unsafe workflow mutation was accepted: $label"
  fi
}

"$checker" "$workflow"

expect_rejection root-default-shell \
  $'env:\n  GOTOOLCHAIN: local\n  GOWORK: "off"\n  GOFLAGS: -mod=readonly\n\nconcurrency:' \
  $'env:\n  GOTOOLCHAIN: local\n  GOWORK: "off"\n  GOFLAGS: -mod=readonly\n\ndefaults:\n  run:\n    shell: '\''bash -c "exit 0" -- {0}'\''\n\nconcurrency:'
expect_rejection root-environment-injection \
  $'env:\n  GOTOOLCHAIN: local\n  GOWORK: "off"\n  GOFLAGS: -mod=readonly' \
  $'env:\n  GOTOOLCHAIN: local\n  GOWORK: "off"\n  GOFLAGS: -mod=readonly\n  PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: "1"'
expect_rejection policy-step-shell-bypass \
  $'      - name: Verify browser diagnostic retention policy\n        shell: bash' \
  $'      - name: Verify browser diagnostic retention policy\n        shell: '\''bash -c "exit 0" -- {0}'\'''
expect_rejection short-job-budget \
  $'  public-files-browser-smoke:\n    name: Public-files HTTPS browser smoke (Playwright)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 40' \
  $'  public-files-browser-smoke:\n    name: Public-files HTTPS browser smoke (Playwright)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 30\n    # timeout-minutes: 40'
expect_rejection expanded-job-budget \
  $'  public-files-browser-smoke:\n    name: Public-files HTTPS browser smoke (Playwright)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 40' \
  $'  public-files-browser-smoke:\n    name: Public-files HTTPS browser smoke (Playwright)\n    runs-on: ubuntu-24.04\n    timeout-minutes: 60\n    # timeout-minutes: 40'
expect_rejection ignored-job-failure \
  $'    timeout-minutes: 40\n    steps:' \
  $'    timeout-minutes: 40\n    continue-on-error: true\n    steps:'
expect_rejection short-install-budget \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 20' \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 10\n        # timeout-minutes: 20'
expect_rejection expanded-install-budget \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 20' \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 30\n        # timeout-minutes: 20'
expect_rejection suffix-install-budget \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 20' \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 200'
expect_rejection suffix-boundary-budget \
  $'      - name: Exercise the HTTPS browser boundary\n        timeout-minutes: 15' \
  $'      - name: Exercise the HTTPS browser boundary\n        timeout-minutes: 150'
expect_rejection boundary-shell-bypass \
  $'      - name: Exercise the HTTPS browser boundary\n        timeout-minutes: 15\n        shell: bash' \
  $'      - name: Exercise the HTTPS browser boundary\n        timeout-minutes: 15\n        shell: '\''bash -c "exit 0" -- {0}'\'''
expect_rejection missing-webkit \
  $'            firefox \\\n            webkit' \
  $'            firefox\n            # webkit'
expect_rejection missing-with-deps \
  '            --with-deps \' \
  $'            --no-shell \\\n            # --with-deps \\'
expect_rejection skipped-install-step \
  $'      - name: Install ephemeral browser dependencies\n        timeout-minutes: 20' \
  $'      - name: Install ephemeral browser dependencies\n        if: ${{ false }}\n        timeout-minutes: 20'
expect_rejection extra-script-replacement-step \
  $'      - name: Exercise the HTTPS browser boundary\n        timeout-minutes: 15' \
  $'      - name: Replace browser boundary script\n        run: touch browser-tests/unreviewed-extra-step\n\n      - name: Exercise the HTTPS browser boundary\n        timeout-minutes: 15'
expect_rejection injected-existing-step \
  $'      - name: Exercise browser diagnostic validator negative cases\n        env:\n          RECASAOS_RUNNER_ENVIRONMENT: ${{ runner.environment }}\n        run: >-\n          bash\n          .github/scripts/test-public-files-browser-diagnostics-validator.sh' \
  $'      - name: Exercise browser diagnostic validator negative cases\n        env:\n          RECASAOS_RUNNER_ENVIRONMENT: ${{ runner.environment }}\n        run: |\n          bash .github/scripts/test-public-files-browser-diagnostics-validator.sh\n          printf "exit 0\\n" > .github/scripts/test-public-files-browser.sh'
expect_rejection duplicate-browser-job-name \
  $'  govulncheck:\n    name: Generate and scan reachable Go vulnerabilities' \
  $'  decoy-browser:\n    name: Public-files HTTPS browser smoke (Playwright)\n    runs-on: ubuntu-24.04\n    steps:\n      - name: No-op\n        run: "true"\n\n  govulncheck:\n    name: Generate and scan reachable Go vulnerabilities'
expect_rejection repeated-apt-update \
  $'            webkit\n          sudo env DEBIAN_FRONTEND=noninteractive' \
  $'            webkit\n          sudo apt-get update\n          sudo env DEBIAN_FRONTEND=noninteractive'

printf 'public-files browser diagnostics policy negative tests passed\n'
