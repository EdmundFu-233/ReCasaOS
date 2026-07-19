#!/bin/sh

set -eu

build_path=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
source_binary="${build_path}/sysroot/usr/bin/casaos"
current_binary=$(command -v casaos 2>/dev/null || true)

if [ -z "${current_binary}" ]; then
    echo "No existing CasaOS installation detected; remote migration is not needed."
    exit 0
fi

source_version=$([ -x "${source_binary}" ] && "${source_binary}" -v 2>/dev/null || true)
current_version=$("${current_binary}" -v 2>/dev/null || true)
if [ -n "${source_version}" ] && [ "${source_version}" = "${current_version}" ]; then
    echo "Installed and packaged versions match; remote migration is not needed."
    exit 0
fi

echo "ReCasaOS remote binary migration is disabled until artifacts have pinned digests, signatures, safe extraction, and rollback." >&2
exit 1
