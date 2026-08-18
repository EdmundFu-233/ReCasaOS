#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'Go dependency boundary policy failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repository="$(cd -- "$script_directory/../.." && pwd -P)"
checker_source="$script_directory/check-go-dependency-boundary.go"
mode=${1:---all}
[[ $# -le 1 ]] || fail "usage: check-go-dependency-boundary.sh [--all|--tools-only]"
case "$mode" in
  --all | --tools-only) ;;
  *) fail "unknown dependency boundary mode: $mode" ;;
esac

command -v go >/dev/null 2>&1 || fail "go is unavailable"
[[ -f "$repository/go.mod" && ! -L "$repository/go.mod" ]] ||
  fail "go.mod is missing or symbolic"
[[ -f "$checker_source" && ! -L "$checker_source" ]] ||
  fail "structured dependency checker is missing or symbolic"

workspace="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-go-dependency-boundary.XXXXXX")"
trap 'rm -rf -- "$workspace"' EXIT
mkdir -m 0700 -- "$workspace/go-build-cache"

checker="$workspace/check-go-dependency-boundary"
if ! (cd -- "$repository" && env \
  CGO_ENABLED=0 \
  GOCACHE="$workspace/go-build-cache" \
  GOWORK=off \
  go build -mod=readonly -trimpath -o "$checker" "$checker_source"); then
  fail "could not build the structured dependency checker"
fi
[[ -x "$checker" ]] || fail "structured dependency checker was not produced"

run_repository_graph() {
  local label=$1
  local goarch=$2
  local goarm=$3
  local cgo_enabled=$4
  local include_tests=$5
  local tags=$6
  local race_enabled=${7:-0}
  local -a environment=(
    "GOCACHE=$workspace/go-build-cache"
    GOWORK=off
    GOOS=linux
    "GOARCH=$goarch"
    "CGO_ENABLED=$cgo_enabled"
  )
  local -a arguments=(
    go list
    -mod=readonly
    -deps
    -json=ImportPath,Incomplete,Error,DepsErrors
  )

  if [[ -n "$goarm" ]]; then
    environment+=("GOARM=$goarm")
  fi
  if [[ "$include_tests" == 1 ]]; then
    arguments+=(-test)
  elif [[ "$include_tests" != 0 ]]; then
    fail "invalid include-tests value for $label: $include_tests"
  fi
  if [[ -n "$tags" ]]; then
    arguments+=(-tags "$tags")
  fi
  if [[ "$race_enabled" == 1 ]]; then
    arguments+=(-race)
  elif [[ "$race_enabled" != 0 ]]; then
    fail "invalid race value for $label: $race_enabled"
  fi
  arguments+=(./...)

  if ! (cd -- "$repository" && env "${environment[@]}" "${arguments[@]}") |
    "$checker" -label "$label" -; then
    fail "selected package graph generation or inspection failed: $label"
  fi
}

run_tool_graph() {
  local cgo_enabled=$1
  local label="linux-amd64-tools-cgo${cgo_enabled}"

  if ! (cd -- "$repository" && env \
    GOCACHE="$workspace/go-build-cache" \
    GOWORK=off \
    GOOS=linux \
    GOARCH=amd64 \
    "CGO_ENABLED=$cgo_enabled" \
    go list \
      -mod=readonly \
      -deps \
      -json=ImportPath,Incomplete,Error,DepsErrors \
      tool) | "$checker" -label "$label" -; then
    fail "selected package graph generation or inspection failed: $label"
  fi
}

run_checker_graph() {
  local checker_goos
  local checker_goarch
  checker_goos="$(go env GOOS)"
  checker_goarch="$(go env GOARCH)"
  local label="native-${checker_goos}-${checker_goarch}-boundary-checker-cgo0"

  if ! (cd -- "$repository" && env \
    GOCACHE="$workspace/go-build-cache" \
    GOWORK=off \
    "GOOS=$checker_goos" \
    "GOARCH=$checker_goarch" \
    CGO_ENABLED=0 \
    go list \
      -mod=readonly \
      -deps \
      -json=ImportPath,Incomplete,Error,DepsErrors \
      "$checker_source") | "$checker" -label "$label" -; then
    fail "selected package graph generation or inspection failed: $label"
  fi
}

for cgo_enabled in 0 1; do
  run_tool_graph "$cgo_enabled"
done
run_checker_graph

if [[ "$mode" == --tools-only ]]; then
  printf 'Go tool dependency boundary preflight passed\n'
  exit 0
fi

# Cover both native Linux test modes, the two privileged tagged harnesses, and
# both CGO modes for every supported release architecture.
run_repository_graph linux-amd64-tests-cgo0 amd64 '' 0 1 ''
run_repository_graph linux-amd64-tests-cgo1 amd64 '' 1 1 ''
run_repository_graph linux-amd64-race-tests-cgo1 amd64 '' 1 1 '' 1
run_repository_graph \
  linux-amd64-browser-tests-cgo0 \
  amd64 '' 0 1 \
  'netgo osusergo recasaos_publicfiles_browser_test'
run_repository_graph \
  linux-amd64-systemd-tests-cgo0 \
  amd64 '' 0 1 \
  'netgo osusergo recasaos_publicfiles_systemd_test'
for architecture in amd64 arm64 arm riscv64; do
  goarm=''
  label_architecture=$architecture
  if [[ "$architecture" == arm ]]; then
    goarm=7
    label_architecture=armv7
  fi
  for cgo_enabled in 0 1; do
    run_repository_graph \
      "linux-${label_architecture}-release-cgo${cgo_enabled}" \
      "$architecture" \
      "$goarm" \
      "$cgo_enabled" \
      0 \
      'musl netgo osusergo'
  done
done

printf 'Go dependency boundary policy passed\n'
