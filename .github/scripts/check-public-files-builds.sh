#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

die() {
  printf 'public-file build check failed: %s\n' "$*" >&2
  exit 1
}

command -v go >/dev/null 2>&1 || die "go is unavailable"
command -v file >/dev/null 2>&1 || die "file is unavailable"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
cd -- "$repo_root"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-public-files-builds.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

build_target() {
  local goarch="$1"
  local goarm="$2"
  local label="$3"
  local expected_machine="$4"
  local binary="$work_dir/recasaos-public-files-$label"
  local description
  local -a build_env=(
    CGO_ENABLED=0
    GOOS=linux
    "GOARCH=$goarch"
    "GOCACHE=$work_dir/go-cache-$label"
  )

  if [[ -n "$goarm" ]]; then
    build_env+=("GOARM=$goarm")
  fi
  env "${build_env[@]}" \
    go build \
      -trimpath \
      -tags 'netgo osusergo' \
      -ldflags '-X main.version=ci-build-check -s -w' \
      -o "$binary" \
      ./cmd/recasaos-public-files

  description="$(file "$binary")"
  grep -q 'ELF' <<<"$description" ||
    die "$label output is not a Linux ELF"
  grep -q 'statically linked' <<<"$description" ||
    die "$label output is not statically linked"
  grep -Fq -- "$expected_machine" <<<"$description" ||
    die "$label output has the wrong ELF machine: $description"
  [[ -x "$binary" ]] || die "$label output is not executable"
}

build_target amd64 "" amd64 'x86-64'
build_target arm64 "" arm64 'ARM aarch64'
build_target arm 7 arm-7 'ARM, EABI5'
build_target riscv64 "" riscv64 'UCB RISC-V'

printf '%s\n' \
  'public-file build check passed: amd64, arm64, armv7, riscv64 static Linux ELF'
