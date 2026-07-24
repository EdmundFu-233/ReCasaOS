#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

die() {
  printf 'GoReleaser configuration check failed: %s\n' "$*" >&2
  exit 1
}

version='2.17.0'
case "$(uname -s):$(uname -m)" in
  Linux:x86_64)
    archive='goreleaser_Linux_x86_64.tar.gz'
    expected_sha256='dde10e2d5a13cef969c0eec00c74f359c0ac306d702b1bd291ad9337b4e54c1d'
    ;;
  Darwin:arm64)
    archive='goreleaser_Darwin_arm64.tar.gz'
    expected_sha256='58912a80159199c0fd5c8484e4c868bf87414129655d6d87cd1cd84ee645736c'
    ;;
  *)
    die "unsupported checker platform: $(uname -s)/$(uname -m)"
    ;;
esac

for required_tool in curl tar; do
  command -v "$required_tool" >/dev/null 2>&1 ||
    die "$required_tool is unavailable"
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-goreleaser-check.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

archive_path="$work_dir/$archive"
curl \
  --proto '=https' \
  --tlsv1.2 \
  --fail \
  --silent \
  --show-error \
  --location \
  --output "$archive_path" \
  "https://github.com/goreleaser/goreleaser/releases/download/v${version}/${archive}"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256="$(sha256sum "$archive_path" | awk '{ print $1 }')"
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256="$(shasum -a 256 "$archive_path" | awk '{ print $1 }')"
else
  die "neither sha256sum nor shasum is available"
fi
[[ "$actual_sha256" == "$expected_sha256" ]] ||
  die "downloaded GoReleaser archive has an unexpected SHA-256"

tar -xzf "$archive_path" -C "$work_dir" goreleaser
[[ -x "$work_dir/goreleaser" ]] ||
  die "verified archive did not contain an executable GoReleaser binary"

"$work_dir/goreleaser" check \
  "$repo_root/.goreleaser.yaml" \
  "$repo_root/.goreleaser.debug.yaml"
