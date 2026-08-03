#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

fail() {
  printf 'public-files browser test failed: %s\n' "$*" >&2
  exit 1
}

[[ "${GITHUB_ACTIONS:-}" == true ]] ||
  fail "this trust-store test is restricted to GitHub Actions"
[[ "${GITHUB_REPOSITORY:-}" == "EdmundFu-233/ReCasaOS" ]] ||
  fail "the repository identity is not the trusted ReCasaOS repository"
[[ "${RUNNER_OS:-}" == Linux ]] ||
  fail "the runner is not Linux"
[[ "${RECASAOS_RUNNER_ENVIRONMENT:-}" == github-hosted ]] ||
  fail "GitHub did not identify this as a hosted runner"
[[ -d /opt/hostedtoolcache ]] ||
  fail "the GitHub-hosted runner marker is missing"
[[ "${GITHUB_RUN_ID:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ID is missing or unsafe"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[0-9]+$ ]] ||
  fail "GITHUB_RUN_ATTEMPT is missing or unsafe"
[[ -n "${RUNNER_TEMP:-}" && -d "$RUNNER_TEMP" && ! -L "$RUNNER_TEMP" ]] ||
  fail "RUNNER_TEMP is missing or unsafe"

command -v certutil >/dev/null 2>&1 ||
  fail "certutil is unavailable"
command -v openssl >/dev/null 2>&1 ||
  fail "openssl is unavailable"
command -v update-ca-certificates >/dev/null 2>&1 ||
  fail "update-ca-certificates is unavailable"
command -v unzip >/dev/null 2>&1 ||
  fail "unzip is unavailable"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
runner_temp="$(realpath -e -- "$RUNNER_TEMP")"
[[ "$runner_temp" == /home/runner/work/_temp ]] ||
  fail "RUNNER_TEMP is not the exact GitHub-hosted Ubuntu path"
[[ "$(stat -c %u "$runner_temp")" == "$(id -u)" ]] ||
  fail "RUNNER_TEMP is not owned by the runner"

run_key="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
workspace="${runner_temp}/recasaos-browser-${run_key}"
diagnostics_directory="${runner_temp}/recasaos-browser-diagnostics-${run_key}"
ca_key="${workspace}/ca.key"
ca_certificate="${workspace}/ca.crt"
server_key="${workspace}/server.key"
server_request="${workspace}/server.csr"
server_certificate="${workspace}/server.crt"
server_extensions="${workspace}/server.ext"
system_ca="/usr/local/share/ca-certificates/recasaos-browser-${run_key}.crt"
nss_nickname="ReCasaOS browser test CA ${run_key}"
runner_home="$(
  getent passwd "$(id -u)" |
    awk -F: 'NR == 1 && NF == 7 { print $6 }'
)"
[[ "$runner_home" == /home/runner ]] ||
  fail "the GitHub runner home directory is unexpected"
nss_database="${runner_home}/.pki/nssdb"
harness="${workspace}/recasaos-public-files-browser-harness"
system_ca_installed=0
nss_ca_installed=0

case "$workspace" in
  /home/runner/work/_temp/recasaos-browser-[0-9]*-[0-9]*) ;;
  *) fail "refusing unsafe browser workspace: $workspace" ;;
esac
case "$diagnostics_directory" in
  /home/runner/work/_temp/recasaos-browser-diagnostics-[0-9]*-[0-9]*) ;;
  *) fail "refusing unsafe browser diagnostics directory" ;;
esac
[[ "$system_ca" =~ ^/usr/local/share/ca-certificates/recasaos-browser-[0-9]+-[0-9]+\.crt$ ]] ||
  fail "refusing unsafe system CA path"
[[ ! -e "$workspace" && ! -L "$workspace" ]] ||
  fail "browser workspace already exists"
[[ ! -e "$diagnostics_directory" && ! -L "$diagnostics_directory" ]] ||
  fail "browser diagnostics directory already exists"
sudo test ! -e "$system_ca" ||
  fail "ephemeral system CA path already exists"

cleanup() {
  local status=$?
  local cleanup_failed=0
  trap - EXIT
  set +e

  if [[ "$nss_ca_installed" == 1 ]]; then
    certutil -D \
      -d "sql:${nss_database}" \
      -n "$nss_nickname" >/dev/null 2>&1 ||
      cleanup_failed=1
  fi
  if [[ "$system_ca_installed" == 1 ]]; then
    sudo rm -f -- "$system_ca" || cleanup_failed=1
    sudo update-ca-certificates >/dev/null 2>&1 || cleanup_failed=1
  fi
  if [[ -e "$workspace" || -L "$workspace" ]]; then
    case "$workspace" in
      /home/runner/work/_temp/recasaos-browser-[0-9]*-[0-9]*)
        rm -rf -- "$workspace" || cleanup_failed=1
        ;;
      *)
        printf 'refusing unsafe browser workspace cleanup: %s\n' \
          "$workspace" >&2
        cleanup_failed=1
        ;;
    esac
  fi
  if [[ -e "$workspace" || -L "$workspace" ]]; then
    cleanup_failed=1
  fi
  if [[ "$status" == 0 && ( -e "$diagnostics_directory" || -L "$diagnostics_directory" ) ]]; then
    case "$diagnostics_directory" in
      /home/runner/work/_temp/recasaos-browser-diagnostics-[0-9]*-[0-9]*)
        rm -rf -- "$diagnostics_directory" || cleanup_failed=1
        ;;
      *)
        cleanup_failed=1
        ;;
    esac
  fi

  if [[ "$cleanup_failed" != 0 ]]; then
    printf 'public-files browser test cleanup failed\n' >&2
    exit 1
  fi
  exit "$status"
}
trap cleanup EXIT

install -d -m 0700 "$workspace"
install -d -m 0700 "$diagnostics_directory"
umask 077

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$ca_key" >/dev/null 2>&1
openssl req \
  -x509 \
  -new \
  -sha256 \
  -days 1 \
  -key "$ca_key" \
  -out "$ca_certificate" \
  -subj "/CN=ReCasaOS ephemeral browser test CA ${run_key}" \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -addext 'subjectKeyIdentifier=hash'

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$server_key" >/dev/null 2>&1
openssl req \
  -new \
  -sha256 \
  -key "$server_key" \
  -out "$server_request" \
  -subj '/CN=127.0.0.1'
{
  printf '%s\n' \
    'basicConstraints=critical,CA:FALSE' \
    'keyUsage=critical,digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=IP:127.0.0.1' \
    'subjectKeyIdentifier=hash' \
    'authorityKeyIdentifier=keyid,issuer'
} >"$server_extensions"
openssl x509 \
  -req \
  -sha256 \
  -days 1 \
  -in "$server_request" \
  -CA "$ca_certificate" \
  -CAkey "$ca_key" \
  -CAcreateserial \
  -out "$server_certificate" \
  -extfile "$server_extensions"

chmod 0600 "$ca_key" "$server_key"
chmod 0644 "$ca_certificate" "$server_certificate"
openssl verify -CAfile "$ca_certificate" "$server_certificate" >/dev/null
openssl x509 -checkend 1 -noout -in "$ca_certificate" >/dev/null
openssl x509 -checkend 1 -noout -in "$server_certificate" >/dev/null

sudo install -o root -g root -m 0644 "$ca_certificate" "$system_ca"
system_ca_installed=1
sudo update-ca-certificates >/dev/null
sudo cmp -s -- "$ca_certificate" "$system_ca" ||
  fail "installed system CA bytes were not preserved"

install -d -m 0700 "$nss_database"
if [[ ! -f "$nss_database/cert9.db" ]]; then
  certutil -N -d "sql:${nss_database}" --empty-password
fi
if certutil -L -d "sql:${nss_database}" -n "$nss_nickname" >/dev/null 2>&1; then
  fail "ephemeral NSS CA nickname already exists"
fi
certutil -A \
  -d "sql:${nss_database}" \
  -n "$nss_nickname" \
  -t 'C,,' \
  -i "$ca_certificate"
nss_ca_installed=1
certutil -L \
  -d "sql:${nss_database}" \
  -n "$nss_nickname" >/dev/null

CGO_ENABLED=0 go test \
  -count=1 \
  -tags 'netgo osusergo recasaos_publicfiles_browser_test' \
  ./browser-tests/harness
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build \
    -trimpath \
    -tags 'netgo osusergo recasaos_publicfiles_browser_test' \
    -o "$harness" \
    ./browser-tests/harness
[[ -x "$harness" && ! -L "$harness" ]] ||
  fail "browser harness build is missing or unsafe"

export RECASAOS_BROWSER_HARNESS="$harness"
export RECASAOS_BROWSER_CA_CERTIFICATE="$ca_certificate"
export RECASAOS_BROWSER_CERTIFICATE="$server_certificate"
export RECASAOS_BROWSER_PRIVATE_KEY="$server_key"
export RECASAOS_BROWSER_DIAGNOSTICS_DIRECTORY="$diagnostics_directory"
export RECASAOS_BROWSER_TEST=1
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

npm --prefix "$repo_root/browser-tests" run smoke
