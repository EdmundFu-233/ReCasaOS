#!/usr/bin/env bash
set -Eeuo pipefail

fail() {
  printf 'API generation recovery test failed: %s\n' "$*" >&2
  exit 1
}

script_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
test_directory="$(mktemp -d)"
trap 'rm -rf -- "$test_directory"' EXIT
mkdir "$test_directory/bin"

# The faulting generator writes partial bytes before failing, reproducing a
# failed fetch/generation without network access or a real API dependency.
cat >"$test_directory/bin/go" <<'GENERATOR'
#!/usr/bin/env bash
set -eu
case " $* " in
  *' -package codegen '*) package=codegen ;;
  *' -package message_bus '*) package=message_bus ;;
  *) exit 90 ;;
esac
case "$GENERATION_TEST_MODE:$package" in
  first-fails:codegen | second-fails:message_bus)
    printf 'partial generator output\n'
    exit 23
    ;;
  invalid-output:message_bus)
    printf 'package broken(\n'
    exit 0
    ;;
  empty-output:message_bus) exit 0 ;;
esac
printf 'package %s\n\nconst Generated = true\n' "$package"
GENERATOR
chmod 0755 "$test_directory/bin/go"

for mode in first-fails second-fails invalid-output empty-output success; do
  fixture="$test_directory/$mode"
  mkdir -p "$fixture/.github/scripts" "$fixture/codegen/message_bus"
  cp "$script_directory/generate-api.sh" "$fixture/.github/scripts/"
  printf 'original casaos client\n' >"$fixture/codegen/casaos_api.go"
  printf 'original MessageBus client\n' >"$fixture/codegen/message_bus/api.go"
  cp "$fixture/codegen/casaos_api.go" "$fixture/casaos.before"
  cp "$fixture/codegen/message_bus/api.go" "$fixture/message_bus.before"

  result=0
  GENERATION_TEST_MODE="$mode" PATH="$test_directory/bin:$PATH" \
    bash "$fixture/.github/scripts/generate-api.sh" \
    >"$fixture/output.log" 2>&1 || result=$?
  if [[ "$mode" == success ]]; then
    [[ "$result" == 0 ]] || fail 'successful generation was rejected'
    printf 'package codegen\n\nconst Generated = true\n' >"$fixture/casaos.expected"
    printf 'package message_bus\n\nconst Generated = true\n' >"$fixture/message_bus.expected"
    cmp "$fixture/casaos.expected" "$fixture/codegen/casaos_api.go" ||
      fail 'successful CasaOS client was not published'
    cmp "$fixture/message_bus.expected" "$fixture/codegen/message_bus/api.go" ||
      fail 'successful MessageBus client was not published'
  else
    [[ "$result" != 0 ]] || fail "$mode was incorrectly accepted"
    cmp "$fixture/casaos.before" "$fixture/codegen/casaos_api.go" ||
      fail "$mode changed the existing CasaOS client"
    cmp "$fixture/message_bus.before" "$fixture/codegen/message_bus/api.go" ||
      fail "$mode changed the existing MessageBus client"
  fi
  for leftover in "$fixture"/codegen/.api-generation.*; do
    [[ ! -e "$leftover" ]] || fail "$mode leaked staging files"
  done
done

printf 'API generation recovery tests passed\n'
