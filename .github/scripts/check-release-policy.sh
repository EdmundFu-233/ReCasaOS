#!/bin/sh

set -eu

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

for config in .goreleaser.yaml .goreleaser.debug.yaml; do
    if ! awk '
        $0 == "release:" {
            in_release = 1
            release_sections++
            next
        }
        in_release && /^[^[:space:]#]/ {
            in_release = 0
        }
        in_release &&
            /^[[:space:]]+disable:[[:space:]]+true[[:space:]]*$/ {
            disabled_release_sections++
        }
        END {
            if (release_sections != 1 ||
                disabled_release_sections != 1) {
                exit 1
            }
        }
    ' "$config"; then
        echo "Release policy violation: $config must keep release.disable: true." >&2
        exit 1
    fi
done
