#!/bin/sh

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd -P)
cd -- "$repo_root"

command -v go >/dev/null 2>&1 || {
    echo "Release policy violation: Go is unavailable for the component-lock checker." >&2
    exit 1
}
env \
    CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOWORK=off \
    go run -mod=readonly .github/scripts/check-component-lock.go

update_path="build/sysroot/usr/share/casaos/shell/update.sh"
migration_path="build/scripts/migration"
for scan_path in "$update_path" "$migration_path"; do
    if [ ! -e "$scan_path" ] || [ -L "$scan_path" ] || [ ! -r "$scan_path" ]; then
        echo "Release policy violation: missing or unsafe scan target: $scan_path" >&2
        exit 1
    fi
done
[ -f "$update_path" ] || {
    echo "Release policy violation: updater scan target is not a file." >&2
    exit 1
}
[ -d "$migration_path" ] || {
    echo "Release policy violation: migration scan target is not a directory." >&2
    exit 1
}

for scan_path in "$update_path" "$migration_path"; do
    if grep -ERn \
        'curl|wget|raw\.githubusercontent\.com|github\.com/.*/releases/download|tar[[:space:]].*x' \
        "$scan_path"
    then
        echo "Release policy violation: updater and migration paths must remain offline and fail closed." >&2
        exit 1
    else
        grep_status=$?
        if [ "$grep_status" -ne 1 ]; then
            echo "Release policy violation: could not inspect $scan_path (grep status $grep_status)." >&2
            exit 1
        fi
    fi
done
