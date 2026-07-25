#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

die() {
  printf 'public-file service boundary check failed: %s\n' "$*" >&2
  exit 1
}

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/../.." && pwd -P)"
cd -- "$repo_root"

command -v go >/dev/null 2>&1 || die "go is unavailable"
[[ -f main.go ]] || die "root main.go is missing"
[[ -d cmd/recasaos-public-files ]] || die "public-file service command is missing"
compgen -G 'cmd/recasaos-public-files/*.go' >/dev/null ||
  die "public-file service command has no Go source"
production_main="cmd/recasaos-public-files/main_linux.go"
[[ -f "$production_main" ]] ||
  die "public-file service Linux entrypoint is missing"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/recasaos-public-files-boundary.XXXXXX")"
trap 'rm -rf -- "$work_dir"' EXIT

root_deps="$work_dir/root-deps.txt"
portal_deps="$work_dir/portal-deps.txt"
go_cache="$work_dir/go-build-cache"
mkdir -p -- "$go_cache"

dependency_has_prefix() {
  local dependency_file="$1"
  local forbidden_prefix="$2"
  local dependency

  while IFS= read -r dependency; do
    if [[ "$dependency" == "$forbidden_prefix" ||
      "$dependency" == "$forbidden_prefix/"* ]]; then
      return 0
    fi
  done <"$dependency_file"

  return 1
}

CGO_ENABLED=0 GOOS=linux GOCACHE="$go_cache" go list -deps . >"$root_deps" ||
  die "go list failed for the root daemon"
[[ -s "$root_deps" ]] || die "root daemon dependency list is empty"

CGO_ENABLED=0 GOOS=linux GOCACHE="$go_cache" \
  go list -deps -tags 'netgo osusergo' \
  ./cmd/recasaos-public-files >"$portal_deps" ||
  die "go list failed for the public-file service"
[[ -s "$portal_deps" ]] || die "public-file service dependency list is empty"

module_path="github.com/IceWhaleTech/CasaOS"
if dependency_has_prefix "$root_deps" "${module_path}/pkg/publicfiles"; then
  die "root daemon still depends on pkg/publicfiles"
fi

for forbidden_prefix in \
  "${module_path}/route" \
  "${module_path}/service" \
  "${module_path}/pkg/sqlite" \
  "${module_path}/pkg/samba" \
  "${module_path}/pkg/filesecurity" \
  "github.com/glebarez/sqlite" \
  "github.com/glebarez/go-sqlite" \
  "gorm.io" \
  "modernc.org/sqlite"
do
  if dependency_has_prefix "$portal_deps" "$forbidden_prefix"; then
    die "public-file service has forbidden dependency prefix: ${forbidden_prefix}"
  fi
done

while IFS= read -r dependency; do
  if [[ "$dependency" == "$module_path/"* &&
    "$dependency" != "${module_path}/cmd/recasaos-public-files" &&
    "$dependency" != "${module_path}/pkg/publicfiles" &&
    "$dependency" != "${module_path}/pkg/publicfiles/"* ]]; then
    die "public-file service has unapproved ReCasaOS dependency: ${dependency}"
  fi
done <"$portal_deps"

grep -Eq \
  '^[[:space:]]*publicFilesTombstonePath[[:space:]]*=[[:space:]]*"/public-files"[[:space:]]*$' \
  main.go ||
  die "root main.go does not retain the /public-files tombstone path"

grep -Eq \
  '"public-files"[[:space:]]*:[[:space:]]*http\.NotFoundHandler\(\)' \
  main.go ||
  die "root main.go does not map /public-files to the 404 tombstone handler"

for forbidden_root_text in \
  "${module_path}/pkg/publicfiles" \
  "publicfiles.NewFromEnv" \
  "NewFromEnv" \
  "ListenAddressFromEnv" \
  "NewHTTPServer" \
  "RECASAOS_PUBLIC_FILE_LISTEN" \
  "publicFilePortal" \
  "publicListener" \
  "netutil.LimitListener"
do
  if grep -Fq -- "$forbidden_root_text" main.go; then
    die "root main.go contains forbidden public portal text: ${forbidden_root_text}"
  fi
done

for forbidden_legacy_api in \
  'func NewFromEnv(' \
  'func ListenAddressFromEnv('
do
  if grep -R -F --include='*.go' -- "$forbidden_legacy_api" \
    pkg/publicfiles >/dev/null; then
    die "pkg/publicfiles retains forbidden environment API: ${forbidden_legacy_api}"
  fi
done

isolated_constructor_count="$(
  grep -Ec 'return[[:space:]]+publicfiles\.NewIsolated\(config\)' \
    "$production_main" || true
)"
[[ "$isolated_constructor_count" == 1 ]] ||
  die "production portal must call publicfiles.NewIsolated exactly once"
if grep -Eq 'return[[:space:]]+publicfiles\.New\(config\)' "$production_main"; then
  die "production portal must not use the in-process publicfiles.New constructor"
fi
worker_dispatch_count="$(
  grep -Ec 'publicfiles\.RunInternalStorageWorker\(os\.Args\[2\]\)' \
    "$production_main" || true
)"
[[ "$worker_dispatch_count" == 1 ]] ||
  die "production entrypoint must dispatch the internal storage worker exactly once"

root_listener_count="$(grep -Ec 'net\.Listen[[:space:]]*\(' main.go || true)"
[[ "$root_listener_count" == "1" ]] ||
  die "root main.go must retain only its single internal net.Listen call"

grep -Eq \
  'net\.Listen\("tcp",[[:space:]]*net\.JoinHostPort\(LOCALHOST,[[:space:]]*"0"\)\)' \
  main.go ||
  die "root main.go net.Listen call is not the localhost-only internal listener"

printf 'public-file service boundary check passed\n'
