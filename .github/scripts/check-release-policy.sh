#!/bin/sh

set -eu

scan_paths="build/sysroot/usr/share/casaos/shell/update.sh build/scripts/migration"

if grep -ERn 'curl|wget|raw\.githubusercontent\.com|github\.com/.*/releases/download|tar[[:space:]].*x' ${scan_paths}; then
    echo "Release policy violation: updater and migration paths must remain offline and fail closed." >&2
    exit 1
fi
