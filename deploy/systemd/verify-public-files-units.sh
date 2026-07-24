#!/bin/sh
set -eu

fail() {
  printf '%s\n' "public-files semantic unit verification: $*" >&2
  exit 1
}

case "$#" in
  3 | 5) ;;
  *)
    fail \
      'usage: verify-public-files-units.sh SERVICE SOCKET BINARY [SERVICE_DROP_IN SOCKET_DROP_IN]'
    ;;
esac

service=$1
socket=$2
binary=$3

for control_file in "$service" "$socket"; do
  test -f "$control_file" ||
    fail "control file is missing or not regular: $control_file"
  test ! -L "$control_file" ||
    fail "control file is a symlink: $control_file"
  test -r "$control_file" ||
    fail "control file is unreadable: $control_file"
done
test -f "$binary" || fail "binary is missing or not regular: $binary"
test ! -L "$binary" || fail "binary is a symlink: $binary"
test -x "$binary" || fail "binary is not executable: $binary"

if test "$#" -eq 5; then
  service_drop_in=$4
  socket_drop_in=$5
  for drop_in in "$service_drop_in" "$socket_drop_in"; do
    test -f "$drop_in" ||
      fail "drop-in is missing or not regular: $drop_in"
    test ! -L "$drop_in" || fail "drop-in is a symlink: $drop_in"
    test -r "$drop_in" || fail "drop-in is unreadable: $drop_in"
  done
fi

for required_tool in awk install mktemp sed systemd-analyze; do
  command -v "$required_tool" >/dev/null 2>&1 ||
    fail "required tool is unavailable: $required_tool"
done

safe_verify_dir_name() {
  candidate=$1
  case "$candidate" in
    /tmp/recasaos-systemd-verify.*)
      suffix=${candidate#/tmp/recasaos-systemd-verify.}
      case "$suffix" in
        ??????) ;;
        *) return 1 ;;
      esac
      case "$suffix" in
        *[!A-Za-z0-9]*) return 1 ;;
      esac
      ;;
    *) return 1 ;;
  esac
}

verify_dir=$(mktemp -d /tmp/recasaos-systemd-verify.XXXXXX)
safe_verify_dir_name "$verify_dir" ||
  fail "mktemp returned an unsafe directory: $verify_dir"
test -d "$verify_dir" && test ! -L "$verify_dir" ||
  fail "mktemp did not create a safe directory: $verify_dir"

cleanup_verify_dir() {
  if test -n "${verify_dir:-}" && safe_verify_dir_name "$verify_dir"; then
    if test -d "$verify_dir" && test ! -L "$verify_dir"; then
      rm -rf -- "$verify_dir"
    elif test -e "$verify_dir" || test -L "$verify_dir"; then
      printf '%s\n' \
        "public-files semantic unit verification: retained unsafe cleanup target: $verify_dir" \
        >&2
    fi
    verify_dir=
  fi
}

handle_signal() {
  signal_status=$1
  trap - 0 1 2 15
  cleanup_verify_dir
  exit "$signal_status"
}
trap cleanup_verify_dir 0
trap 'handle_signal 129' 1
trap 'handle_signal 130' 2
trap 'handle_signal 143' 15

verify_service="${verify_dir}/recasaos-public-files.service"
verify_socket="${verify_dir}/recasaos-public-files.socket"
verify_binary="${verify_dir}/recasaos-public-files"
verify_output="${verify_dir}/systemd-analyze.output"

install -m 0755 "$binary" "$verify_binary"
install -m 0644 "$socket" "$verify_socket"
awk -v executable="$verify_binary" '
  BEGIN { replacements = 0 }
  /^ExecStart=\/usr\/bin\/recasaos-public-files / {
    sub(/^ExecStart=\/usr\/bin\/recasaos-public-files /, "ExecStart=" executable " ")
    replacements++
  }
  { print }
  END {
    if (replacements != 1)
      exit 1
  }
' "$service" >"$verify_service" ||
  fail 'the service does not contain exactly one reviewed ExecStart prefix'
chmod 0644 "$verify_service"

if test "$#" -eq 5; then
  install -d -m 0755 \
    "${verify_service}.d" \
    "${verify_socket}.d"
  install -m 0644 "$service_drop_in" "${verify_service}.d/ci.conf"
  install -m 0644 "$socket_drop_in" "${verify_socket}.d/ci.conf"
fi

if ! systemd-analyze verify "$verify_socket" "$verify_service" \
  >"$verify_output" 2>&1; then
  sed 's/^/systemd-analyze: /' "$verify_output" >&2
  fail 'unit verification failed'
fi
if test -s "$verify_output"; then
  sed 's/^/systemd-analyze: /' "$verify_output" >&2
  fail 'unit verification emitted warnings'
fi

cleanup_verify_dir
trap - 0 1 2 15
printf '%s\n' 'public-files semantic unit verification: passed'
