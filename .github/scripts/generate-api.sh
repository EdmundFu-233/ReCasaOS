#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd -- "$repository_root"
mkdir -p codegen/message_bus
generation_directory="$(mktemp -d codegen/.api-generation.XXXXXX)"
trap 'rm -rf -- "$generation_directory"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Redirection must never truncate a committed client before the generator has
# succeeded. Prepare and syntax-check both results before publishing either.
go tool oapi-codegen -generate types,server,spec -package codegen \
  api/casaos/openapi.yaml >"$generation_directory/casaos_api.go"
go tool oapi-codegen -generate types,client -package message_bus \
  https://raw.githubusercontent.com/IceWhaleTech/CasaOS-MessageBus/ba87168fcfa4ac5ff7a114f66a139eb5fe427646/api/message_bus/openapi.yaml \
  >"$generation_directory/message_bus_api.go"
test -s "$generation_directory/casaos_api.go"
test -s "$generation_directory/message_bus_api.go"
gofmt -w "$generation_directory/casaos_api.go" "$generation_directory/message_bus_api.go"
chmod 0644 "$generation_directory/casaos_api.go" "$generation_directory/message_bus_api.go"

# Each rename is on the destination filesystem. This is not a two-file
# transaction across process crashes or a failed publication rename.
mv -f -- "$generation_directory/casaos_api.go" codegen/casaos_api.go
mv -f -- "$generation_directory/message_bus_api.go" codegen/message_bus/api.go
printf 'API clients generated successfully\n'
