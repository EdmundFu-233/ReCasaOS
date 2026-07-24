# Read-only public file portal deployment

## Readiness boundary

ReCasaOS now includes a dedicated, opt-in, read-only public file portal at
`/public-files/`. It listens separately from Gateway and is the only route
intended for a public hostname. The full CasaOS dashboard, Gateway, v1/v2/v3
APIs, setup, SSH terminal, Samba, storage administration, and cloud
integrations are **not** part of this boundary and must remain on a private
management network or mesh VPN.

The supplied Caddy and Nginx examples use a positive route allowlist: they
proxy `/public-files` and `/public-files/*`, then return 404 for everything
else. Do not replace that final deny with a catch-all proxy.

This guide is a repository deployment baseline, not evidence of a live public
deployment. The repository has not verified any real public hostname, DNS
record, certificate, firewall policy, running reverse proxy, external port
scan, or Internet acceptance test. The `.invalid` names and documentation IPs
in the examples are placeholders. A specific host remains unverified until an
operator completes and records every applicable acceptance test below.

Verifier-only provisioning removes the raw bearer from the server filesystem,
but it does not isolate the listener from the privileged daemon.
[Issue #25](https://github.com/EdmundFu-233/ReCasaOS/issues/25) remains a
production public-readiness blocker regardless of whether the credential
migration below succeeds.

The portal is deliberately limited:

- read-only directory listing and regular-file download;
- a server-configured root that cannot be `/`;
- a 47-character `rc1_` bearer generated and retained off-host, while the
  server loads only its strict versioned SHA-256 verifier;
- header-only authentication (tokens in query strings are rejected);
- Linux `openat2` descriptor-relative access with `RESOLVE_BENEATH`,
  `NO_SYMLINKS`, `NO_MAGICLINKS`, and `NO_XDEV`;
- pinned-descriptor `statx` mount identity and `fstatfs` type checks before the
  portal is returned, with no unrestricted filesystem fallback;
- no hidden files, symlinks, hard-linked files, devices, sockets, pipes, or
  mount-boundary traversal;
- bounded directory listings, strict browser CSP, no-store responses, and no
  external browser assets.

### Browser download boundary (candidate)

The supplied client does not intentionally persist its bearer in cookies, URLs,
history, `sessionStorage`, `localStorage`, IndexedDB, or the Cache API. During
an authorized request it necessarily exists transiently in page memory, one
page-to-Worker message, Worker memory, the `Authorization` header, the TLS edge,
and server request memory. Logout, page exit, and reload clear the page's
reference, but static source tests cannot prove that a browser, extension,
DevTools session, proxy, operating system, or crash reporter retained no copy.

For a large file, a scoped Service Worker first records a 192-bit random,
single-use correlation nonce bound to the exact portal client, relative path,
and same-origin file URL for at most 10 seconds. The page then starts an
ordinary top-level navigation whose fragment contains that non-secret nonce.
The worker consumes the reservation atomically, challenges only the original
portal page over a `MessageChannel`, receives the bearer once, removes the
fragment, and makes one clean same-origin file request with the bearer in the
`Authorization` header. Redirects fail, credentials are omitted, and the
worker requires the exact clean URL, 200/206 status, attachment disposition,
octet-stream type, `no-store`, `nosniff`, and byte-range policy before returning
the upstream streaming response without calling `blob()`, `arrayBuffer()`,
cloning, or teeing the body. A restart loses all transient reservations and
therefore fails closed. Cancellation before response handoff aborts the worker
fetch; browser download cancellation after handoff must still be verified end
to end. If the controlled top-level request reaches the server without
Worker-added authorization, its browser-generated navigation metadata selects
an empty 204 response, so access remains denied without replacing the portal
document; ordinary API clients still receive 401.

This uses a top-level attachment navigation because the HTML navigation model
keeps the existing document when an attachment is handed to the download
manager, while `frame-ancestors 'none'` deliberately blocks an iframe before
the attachment branch. It does not depend on Service Worker interception of an
`<a download>` request or on a navigation `clientId`. See the
[HTML navigation algorithm](https://html.spec.whatwg.org/multipage/browsing-the-web.html#attempting-to-populate-the-history-entry's-document),
the [Service Worker fetch-event tests](https://github.com/web-platform-tests/wpt/blob/master/service-workers/service-worker/fetch-event.https.html),
and the [streaming-response tests](https://github.com/web-platform-tests/wpt/blob/master/service-workers/service-worker/fetch-event-respond-with-readable-stream.https.html).

If that protocol is unavailable before navigation begins, the page permits one
fallback download at a time only when both listing metadata and the response's
mandatory `Content-Length` are safe integers no greater than 32 MiB. It counts
every `ReadableStream` chunk and aborts on an overrun, mismatch, missing body,
or early EOF before constructing a Blob. The 32 MiB figure is a payload cap,
not a promise of 32 MiB peak heap use: chunk storage and Blob construction can
temporarily require roughly two copies plus browser overhead.

This is a candidate implementation for
[Issue #20](https://github.com/EdmundFu-233/ReCasaOS/issues/20), not evidence of
cross-browser readiness. Stable Chromium, Firefox, and WebKit still require
real HTTPS tests covering saved-file contents and names, large/slow-transfer
memory, two tabs, nonce replay, Worker restart, logout, token rotation,
redirects, initial Range, transparent retry/resume, and cancellation. The
current nonce is deliberately one-shot, so a later automatic retry with the
same URL fails closed rather than silently reusing authorization.

The dedicated application server treats 30 seconds without a successful file
write as a stalled download. A cumulative budget also requires at least 64 KiB
per second after a 30-second grace period. Each bounded file-body write can
refresh the idle deadline, so this is not an absolute total-transfer cutoff;
clients that keep acceptable progress may continue for longer than one hour.
These limits protect the finite download slots and do not replace the edge
connection/rate controls or target-host cancellation tests below.

There is intentionally no weaker fallback. The portal now requires Linux 5.8
or newer plus a seccomp profile that permits `openat2`, `statx` mount-ID, and
`fstatfs` checks; missing kernel support or a missing mount identifier fails
startup. A real procfs mounted at `/proc` is also required: verifier and download
files are first pinned with `O_PATH`, then reopened only through the internally
generated `/proc/self/fd/<fd>` path and revalidated. The required verifier read
probes this mechanism during portal initialization, so an unavailable procfd
mechanism also fails startup.

## 1. Prepare the share and verifier-only credential

The supported candidate never provisions or stores the raw bearer as a
server-side credential file or environment setting. Generate it only on an
independent administrator workstation, keep its durable copy only in a password
manager, and send only its verifier as deployment material. The portal still
receives the raw bearer transiently in each authorized request header.
Completing this credential migration does not make the current privileged
in-process portal public-ready; Issue #25 remains open.

Use a dedicated directory containing only files approved for public download.
Do not point it at a home directory, `/DATA`, an application-data tree, backup
root, secrets directory, or a writable upload staging area.

Use a reviewed local filesystem for this root. At startup, ReCasaOS calls
`fstatfs` and `statx(STATX_MNT_ID)` on the descriptor it already pinned, not on
a replaceable pathname. The explicit allowlist is ext2/3/4, XFS, Btrfs, tmpfs,
and F2FS. FUSE, NFS, CIFS/SMB, 9p, Ceph, XenFS, overlayfs, ZFS, bcachefs, and
every unknown or unverified type fail closed with the observed type in the
startup error. ZFS is deliberately excluded until a dedicated Linux/ZFS job
proves the complete `openat2`, mount-ID, procfd reopen, Range, and cancellation
path; do not bypass the policy to obtain compatibility.

A bind mount receives its own mount ID but retains the backing filesystem
type, so it is eligible only when that backing type is allowlisted. Every
descriptor-relative open is rechecked against the root's captured mount ID and
`RESOLVE_NO_XDEV` still rejects nested mount crossings. These checks occur
before a usable Portal or download-slot pool is returned. They prevent a known
network/FUSE root from entering the request path, but they do not make local
kernel or block-device I/O interruptible: a bad disk, remote block device, or
kernel fault can still block, and even the initial startup open can wait on a
path whose kernel lookup is already hung. Filesystem classification itself can
also wait for a broken userspace filesystem daemon. There is no claimed startup
hard timeout. Host storage and the mount namespace remain trusted operator
boundaries. This is a staged control for
[Issue #22](https://github.com/EdmundFu-233/ReCasaOS/issues/22), not proof that
the in-process portal can safely contain every blocking storage failure.
Separating the Internet-facing handler and killable filesystem work from the
privileged daemon remains required by
[Issue #25](https://github.com/EdmundFu-233/ReCasaOS/issues/25).

Privileged bind, tmpfs, and loopback filesystem regressions run only in a
dedicated ephemeral CI job. The compatibility matrix formats and mounts ext4,
XFS, Btrfs, and F2FS, then exercises the pinned-root listing and regular-file
data path; a separate tmpfs test exercises the same path. Ext2 and ext3 share
the ext-family magic but are not independently formatted in this matrix. The
bind replacement test mutates mount topology after the root is pinned and
proves that the live portal remains attached to its original descriptor. These
tests require an explicit environment opt-in and root, refuse to proceed in
PID 1's mount namespace or while any shared propagation remains, and execute
under
`unshare --mount --propagation private`. Ordinary local or unprivileged test
runs skip before making any mount syscall.

### Generate the bearer off-host

Use an independent, trusted administrator workstation rather than the
ReCasaOS host. The raw bearer has exactly 47 ASCII characters: the literal
`rc1_` followed by the base64url-without-padding encoding of 32 random bytes.
The server verifier is the SHA-256 digest of that complete 47-character value,
including the prefix.
The portal rejects noncanonical encodings and obvious low-diversity byte
patterns, but no verifier can prove that a bearer came from a cryptographically
secure generator. The off-host `openssl rand` step is therefore a required
security control, not optional formatting guidance.

The following fail-fast Bash template keeps the raw bearer in a non-exported
shell variable and writes only the verifier file. It intentionally stops at
`false`: replace only that command with the password manager's reviewed
stdin-import command. Running the template unchanged cannot publish a verifier.
The exact import command is intentionally not guessed because password managers
differ.

```bash
(
  set +x
  set -euo pipefail
  umask 077

  bearer="rc1_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n')"
  test "${#bearer}" -eq 47
  digest="$(builtin printf '%s' "$bearer" |
    openssl dgst -sha256 -binary |
    xxd -p -c 256)"
  test "${#digest}" -eq 64

  # Replace `false` with a reviewed password-manager command that reads stdin.
  # Do not echo the bearer or pass it as an external process argument.
  builtin printf '%s' "$bearer" | false

  verifier_tmp="$(mktemp ./recasaos-public-file.verifier.XXXXXX)"
  cleanup_verifier_tmp() {
    test -z "${verifier_tmp:-}" || rm -f -- "$verifier_tmp"
  }
  trap cleanup_verifier_tmp EXIT
  builtin printf 'recasaos-public-verifier-v1:sha256:%s\n' "$digest" \
    > "$verifier_tmp"
  test "$(wc -c < "$verifier_tmp")" -eq 100
  LC_ALL=C grep -Eq \
    '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' \
    "$verifier_tmp"
  mv -f -- "$verifier_tmp" recasaos-public-file.verifier
  verifier_tmp=
  trap - EXIT
  unset bearer digest
)
```

The verifier file is exactly one 100-byte line terminated by one LF:

```text
recasaos-public-verifier-v1:sha256:<64 lowercase hexadecimal characters>
```

Transfer only `recasaos-public-file.verifier` as host provisioning material over
an authenticated channel. Never copy the raw bearer into the host filesystem,
environment, unit file, diagnostic command, shell history, issue, URL, or log.
Authorized clients necessarily send it in an HTTPS `Authorization` header; the
edge and portal must be configured and tested not to log that header.

### Publish the verifier on the host

Create the dedicated share and publish the transferred verifier with a
same-directory rename. Replace `/path/to/transferred.verifier` with the
authenticated transfer destination:

```bash
(
  set -euo pipefail
  verify_verifier_file() {
    test "$(sudo stat -c '%s' "$1")" -eq 100
    sudo env LC_ALL=C grep -Eq \
      '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' "$1"
  }

  verify_verifier_file /path/to/transferred.verifier
  sudo install -d -o root -g root -m 0750 /srv/recasaos-public
  sudo install -d -o root -g root -m 0700 /etc/recasaos
  sudo install -o root -g root -m 0600 \
    /path/to/transferred.verifier \
    /etc/recasaos/public-file.verifier.next
  verify_verifier_file /etc/recasaos/public-file.verifier.next
  sudo mv -f -- \
    /etc/recasaos/public-file.verifier.next \
    /etc/recasaos/public-file.verifier
)
```

The verifier loader requires the exact versioned line, a stable single-link
regular file, service-safe ownership, and restrictive permissions. It rejects
unexpected whitespace, uppercase or non-hexadecimal digest text, links, and
ambiguous legacy input.

Remove `RECASAOS_PUBLIC_FILE_TOKEN_FILE` from every environment file, service
drop-in, container definition, and process-manager setting before restart.
When the portal is enabled, any non-empty value fails closed, including when
`RECASAOS_PUBLIC_FILE_VERIFIER_FILE` is also present. An empty value is treated
as unset. A disabled portal ignores the legacy setting entirely so an old
template cannot terminate the management daemon, but the setting should still
be removed during migration.
During a first migration, stop public routing, remove the legacy raw-token file
from the host, and do not use that legacy path as rollback. Until those steps
finish, the host is in a maintenance migration state and is not public-ready.

## 2. Enable the verifier-only candidate

This drop-in requires systemd 247 or newer. `LoadCredential=`, the runtime
credential directory, and its `%d` unit specifier are not implied by the Linux
5.8 kernel requirement. Check the actual target host before installing the
drop-in:

```bash
(
  set -euo pipefail
  systemd_version="$(systemd --version | awk 'NR == 1 { print $2 }')"
  test "$systemd_version" -ge 247
)
```

Validate this requirement and the credential file ownership/mode behavior on
every supported target distribution during a maintenance window. Do not
continue unless the version gate exits zero.

Install the reviewed
[`deploy/systemd/recasaos-public-files-verifier.conf.example`](../../deploy/systemd/recasaos-public-files-verifier.conf.example)
as a root-owned `casaos.service` drop-in. The example sets:

```text
RECASAOS_PUBLIC_FILE_ENABLED=1
RECASAOS_PUBLIC_FILE_ROOT=/srv/recasaos-public
RECASAOS_PUBLIC_FILE_VERIFIER_FILE=%d/recasaos-public-file-verifier
RECASAOS_PUBLIC_FILE_LISTEN=127.0.0.1:39777
RECASAOS_TRUST_LOOPBACK_AUTH_BYPASS=0
```

Its `LoadCredential=` directive copies the strict verifier into systemd's
private service credential directory; `%d` expands to that directory. It also
sets `LimitCORE=0`. Do not add `RECASAOS_PUBLIC_FILE_TOKEN_FILE`; any non-empty
value is rejected rather than guessing whether legacy material is a bearer or
a digest.

Example installation from a reviewed checkout:

```bash
(
  set -euo pipefail
  dropin=/etc/systemd/system/casaos.service.d/recasaos-public-files-verifier.conf
  backup_dir=
  backup_dropin=
  staged_dropin=
  recovery_candidate=
  original_identity=
  had_previous_dropin=0
  dropin_modified=0
  restart_attempted=0

  restore_dropin_on_failure() {
    status=$?
    trap - EXIT
    set +e
    recovery_status=0

    if test "$status" -ne 0 && test "$dropin_modified" -eq 1; then
      if test "$had_previous_dropin" -eq 1; then
        if current_identity="$(
          sudo stat -c '%d:%i' -- "$dropin" 2>/dev/null
        )" && test "$current_identity" = "$original_identity"; then
          :
        elif sudo test -f "$backup_dropin" &&
          ! sudo test -L "$backup_dropin"; then
          if sudo test -e "$recovery_candidate" ||
            sudo test -L "$recovery_candidate"; then
            recovery_status=1
          elif ! sudo ln -- "$backup_dropin" "$recovery_candidate"; then
            recovery_status=1
          elif ! sudo mv -fT -- "$recovery_candidate" "$dropin"; then
            recovery_status=1
          elif ! current_identity="$(
            sudo stat -c '%d:%i' -- "$dropin"
          )" || test "$current_identity" != "$original_identity"; then
            recovery_status=1
          fi
        else
          recovery_status=1
        fi
      else
        sudo rm -f -- "$dropin" || recovery_status=1
      fi

      if test "$recovery_status" -eq 0; then
        sudo systemctl daemon-reload || recovery_status=1
      fi
      if test "$recovery_status" -eq 0 &&
        test "$restart_attempted" -eq 1; then
        sudo systemctl restart casaos.service || recovery_status=1
        if test "$recovery_status" -eq 0; then
          sudo systemctl is-active --quiet casaos.service ||
            recovery_status=1
        fi
      fi

      if test "$recovery_status" -ne 0; then
        echo "automatic CasaOS drop-in recovery failed" >&2
        echo "keep the maintenance window open; do not restore routing" >&2
        if test -n "$backup_dir"; then
          echo "preserved root-only recovery workspace: $backup_dir" >&2
        else
          echo "inspect the intended drop-in path: $dropin" >&2
        fi
        exit 1
      fi
    fi

    for cleanup_file in \
      "$recovery_candidate" "$staged_dropin" "$backup_dropin"; do
      if test -n "$cleanup_file" &&
        { sudo test -e "$cleanup_file" ||
          sudo test -L "$cleanup_file"; }; then
        if ! sudo unlink -- "$cleanup_file"; then
          echo "root-only recovery artifact remains: $cleanup_file" >&2
        fi
      fi
    done
    if test -n "$backup_dir" && ! sudo rmdir -- "$backup_dir"; then
      echo "root-only recovery workspace remains: $backup_dir" >&2
    fi
    exit "$status"
  }
  trap restore_dropin_on_failure EXIT

  sudo install -d -o root -g root -m 0755 \
    /etc/systemd/system/casaos.service.d
  sudo install -d -o root -g root -m 0700 /etc/recasaos
  if sudo test -L "$dropin"; then
    echo "refusing a symlinked CasaOS drop-in" >&2
    exit 1
  fi
  if sudo test -e "$dropin"; then
    if ! sudo test -f "$dropin"; then
      echo "refusing a non-regular CasaOS drop-in" >&2
      exit 1
    fi
    original_identity="$(sudo stat -c '%d:%i' -- "$dropin")"
    had_previous_dropin=1
  fi

  backup_dir="$(sudo mktemp -d \
    /etc/systemd/system/casaos.service.d/.recasaos-backup.XXXXXX)"
  sudo chmod 0700 "$backup_dir"
  backup_dropin="$backup_dir/original"
  staged_dropin="$backup_dir/pending"
  recovery_candidate="$backup_dir/recovery"

  if test "$had_previous_dropin" -eq 1; then
    sudo ln -- "$dropin" "$backup_dropin"
    test "$(
      sudo stat -c '%d:%i' -- "$backup_dropin"
    )" = "$original_identity"
  fi

  sudo install -o root -g root -m 0644 \
    deploy/systemd/recasaos-public-files-verifier.conf.example \
    "$staged_dropin"

  # Replacing one directory entry on the same filesystem is atomic.
  dropin_modified=1
  sudo mv -fT -- "$staged_dropin" "$dropin"
  selinux_enabled=0
  if test -e /sys/fs/selinux/enforce; then
    selinux_enabled=1
  elif command -v getenforce >/dev/null 2>&1; then
    selinux_state="$(getenforce)"
    if test "$selinux_state" != Disabled; then
      selinux_enabled=1
    fi
  fi
  if test "$selinux_enabled" -eq 1; then
    command -v restorecon >/dev/null 2>&1
    sudo restorecon "$dropin"
  fi

  # This is a hard gate: reload/restart is unreachable when verification fails.
  sudo systemd-analyze verify casaos.service
  sudo systemctl daemon-reload
  restart_attempted=1
  sudo systemctl restart casaos.service
  sudo systemctl is-active --quiet casaos.service

  # The new service is now committed. Cleanup must never roll it back.
  trap - EXIT
  if sudo test -e "$backup_dropin"; then
    sudo unlink -- "$backup_dropin"
  fi
  sudo rmdir -- "$backup_dir"
)
```

The local `EXIT` trap restores the previous drop-in (or removes a first-time
drop-in) and reloads systemd on failure. The backup is a hard link in a
root-only directory on the same filesystem, so restoring it keeps the original
inode, ownership, mode, ACLs, security labels, and extended attributes instead
of relying on a lossy copy. If a restart was already attempted, the trap also
restarts the previous service configuration and verifies that it is active.
The trap deletes the backup only after every required recovery step succeeds.
On any recovery error it exits nonzero, prints the preserved root-only recovery
workspace, and leaves the maintenance window open. Do not restore public
routing until `casaos.service` is active under the intended configuration.
No shell trap can handle `SIGKILL` or a host power loss. After either event,
inspect any root-only `.recasaos-backup.*` workspace in the drop-in directory
and reconcile the recorded original with the active drop-in before continuing.

The enable flag, root, and verifier credential are required. The listener
accepts only a literal loopback IP and canonical port from 1 to 65535;
hostnames, wildcard/public addresses, and port zero make startup fail. An
enabled but unsafe, malformed, legacy, or incomplete configuration fails closed
during startup. Never enable the legacy loopback auth bypass behind a reverse
proxy.

After restart, verify locally that
`127.0.0.1:39777/public-files/` serves the portal. Gateway also registers
`/public-files`, but that handler is a deliberate 404 tombstone used to clear
or prevent a stale historical route. It does not serve files, and the public
edge must never proxy Gateway for this portal. Verify the tombstone returns 404
and that the dashboard remains reachable only through its normal private access
path. Do not print a bearer or verifier during routine diagnostics.

This drop-in still runs the listener inside the privileged management daemon.
It is a verifier migration example, not the least-privileged service boundary
required by Issue #25.

### Rotate, verify, and roll back

Generate each replacement bearer and verifier on the independent administrator
workstation exactly as in section 1. Keep both the previous and pending raw
bearers in the password manager until verification finishes. Transfer only the
pending verifier to the host.

Before publication, retain a root-only rollback copy of the current strict
verifier. Stage the pending verifier in the same directory, then publish it
with one rename and restart the service so systemd creates a new credential
instance:

```bash
(
  set -euo pipefail
  verify_verifier_file() {
    test "$(sudo stat -c '%s' "$1")" -eq 100
    sudo env LC_ALL=C grep -Eq \
      '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' "$1"
  }

  verify_verifier_file /etc/recasaos/public-file.verifier
  verify_verifier_file /path/to/pending.verifier
  sudo install -o root -g root -m 0600 \
    /etc/recasaos/public-file.verifier \
    /etc/recasaos/public-file.verifier.rollback
  verify_verifier_file /etc/recasaos/public-file.verifier.rollback
  sudo install -o root -g root -m 0600 \
    /path/to/pending.verifier \
    /etc/recasaos/public-file.verifier.next
  verify_verifier_file /etc/recasaos/public-file.verifier.next
  sudo mv -f -- \
    /etc/recasaos/public-file.verifier.next \
    /etc/recasaos/public-file.verifier
  sudo systemctl restart casaos.service
  sudo systemctl is-active --quiet casaos.service
)
```

Changing the source verifier without a successful restart does not rotate the
credential already loaded by the running process. From an unrelated client,
require **old = 401** and **new = 200**. The fail-fast template below
intentionally stops at both `false` commands; replace them with reviewed
password-manager commands that print exactly one bearer to stdout for command
substitution. Feeding the header over standard input keeps the bearer out of
the `curl` argument list:

```bash
(
  set +x
  set -euo pipefail
  old_bearer="$(false)" # Replace false with the old-bearer retrieval command.
  new_bearer="$(false)" # Replace false with the new-bearer retrieval command.
  [[ "$old_bearer" =~ ^rc1_[A-Za-z0-9_-]{43}$ ]]
  [[ "$new_bearer" =~ ^rc1_[A-Za-z0-9_-]{43}$ ]]
  old_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$old_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://files.example.net/public-files/api/list?path='
  )"
  new_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$new_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://files.example.net/public-files/api/list?path='
  )"
  test "$old_status" = 401
  test "$new_status" = 200
  unset old_bearer new_bearer old_status new_status
)
```

If restart or either assertion fails, stop public routing, restore the previous
strict verifier with another same-directory rename, restart, and prove the
inverse result—old bearer 200, pending bearer 401—before restoring routing:

```bash
(
  set -euo pipefail
  verify_verifier_file() {
    test "$(sudo stat -c '%s' "$1")" -eq 100
    sudo env LC_ALL=C grep -Eq \
      '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' "$1"
  }

  verify_verifier_file /etc/recasaos/public-file.verifier.rollback
  sudo install -o root -g root -m 0600 \
    /etc/recasaos/public-file.verifier.rollback \
    /etc/recasaos/public-file.verifier.rollback.next
  verify_verifier_file /etc/recasaos/public-file.verifier.rollback.next
  sudo mv -f -- \
    /etc/recasaos/public-file.verifier.rollback.next \
    /etc/recasaos/public-file.verifier
  sudo systemctl restart casaos.service
  sudo systemctl is-active --quiet casaos.service
)
```

From the unrelated client, run this separate inverse gate after rollback. As
above, replace both `false` commands with the reviewed password-manager
retrieval commands:

```bash
(
  set +x
  set -euo pipefail
  old_bearer="$(false)" # Replace false with the old-bearer retrieval command.
  new_bearer="$(false)" # Replace false with the pending-bearer retrieval command.
  [[ "$old_bearer" =~ ^rc1_[A-Za-z0-9_-]{43}$ ]]
  [[ "$new_bearer" =~ ^rc1_[A-Za-z0-9_-]{43}$ ]]
  old_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$old_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://files.example.net/public-files/api/list?path='
  )"
  new_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$new_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://files.example.net/public-files/api/list?path='
  )"
  test "$old_status" = 200
  test "$new_status" = 401
  unset old_bearer new_bearer old_status new_status
)
```

After a successful rotation, remove the rollback verifier according to the
recorded change procedure and retire the old bearer from the password manager.
A first migration from the rejected raw-token configuration has no supported
raw-token rollback: leave the portal disabled if verifier startup or
authentication fails.

## 3. Install a portal-only TLS edge

Choose one example:

- `deploy/caddy/Caddyfile.example` requires stock Caddy 2.11.4 or newer;
- `deploy/nginx/recasaos.conf.example` is intended for a current Nginx `http`
  context.

Before enabling either:

1. Replace every `.invalid`, TEST-NET IPv4, and documentation IPv6 value.
2. Install a publicly trusted certificate and test automatic renewal.
3. Configure the edge's only upstream as the dedicated literal-loopback portal
   listener at `127.0.0.1:39777`. Never point it at Gateway.
4. Move the management Gateway off public edge ports to a non-80 private/VPN
   management port, restrict it with host firewall policy, and bind the edge
   only to the intended public addresses on 80/443.
5. Permit inbound TCP 80/443 only on the public interface. Do not expose SSH,
   Samba, databases, message bus, daemon control, Gateway, the dedicated portal
   listener, or other root-service listener ports.
6. Keep the no-query access-log format. Authorization belongs in the header,
   but query strings can still contain sensitive filenames.
7. Keep the final 404 deny and the 1 MiB request-body ceiling. Portal downloads
   are responses, so large files do not require a large request limit.
8. Keep the edge proxy on a currently supported, fully patched release. The
   Caddy minimum is a security boundary, not permission to defer later patches.

Keep Caddy's `flush_interval` unset as the supplied example does. Caddy's
default behavior partially buffers responses and allows a downstream client
disconnect to cancel the loopback upstream request. A negative value such as
`flush_interval -1` disables that buffering but also keeps the upstream request
running after the client has gone away; do not reintroduce it for downloads.

In the Nginx example, `proxy_read_timeout 3600s` is an upstream-read idle
timeout: it applies between two successive read operations, not to the total
response duration. A continuously progressing download does not expire merely
because its total duration exceeds one hour, although application and other
edge deadlines still apply. The example also leaves `proxy_ignore_client_abort`
at its default `off`, so Nginx does not intentionally keep the loopback
upstream request alive after the downstream client disconnects.

The Nginx example includes per-client request and connection limits. Stock
Caddy has no equivalent request-rate limiter in the supplied example; a public
Caddy deployment therefore requires a separate, reviewed rate-limiting
edge/WAF or another independently verified control in front of it.

HSTS is intentionally scoped to the portal hostname. Add `includeSubDomains`
only after every subdomain is permanently HTTPS-only.

## 4. Acceptance tests

Run these from an unrelated Internet connection and substitute the real
hostname. The template intentionally stops at `false`; replace it with a
reviewed password-manager command that prints exactly one bearer to stdout for
command substitution. Keep `command curl -q` so shell aliases/functions are
bypassed and `-q` remains curl's first argument; this prevents a user `.curlrc`
from enabling verbose/trace logging. Authenticated headers are fed over standard
input so the bearer is not placed in the `curl` argument list:

```bash
(
  set +x
  set -euo pipefail
  test_bearer="$(false)" # Replace false with the retrieval command.
  [[ "$test_bearer" =~ ^rc1_[A-Za-z0-9_-]{43}$ ]]

  page_status="$(command curl -q -sS -o /dev/null -w '%{http_code}' \
    https://files.example.net/public-files/)"
  management_status="$(command curl -q -sS -o /dev/null -w '%{http_code}' \
    https://files.example.net/v1/sys/version/current)"
  unauthenticated_status="$(command curl -q -sS -o /dev/null -w '%{http_code}' \
    https://files.example.net/public-files/api/list)"
  authorized_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$test_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://files.example.net/public-files/api/list?path='
  )"
  query_token_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$test_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://files.example.net/public-files/api/list?token=must-not-be-accepted'
  )"

  test "$page_status" = 200
  test "$management_status" = 404
  test "$unauthenticated_status" = 401
  test "$authorized_status" = 200
  test "$query_token_status" = 400
  unset test_bearer page_status management_status
  unset unauthenticated_status authorized_status query_token_status
)
```

Expected results: the page is 200, the management route is 404, an
unauthenticated list is 401, the authorized list contains only relative minimal
metadata, and the final query-token attempt is 400 without placing the real
token in the URL. Also verify:

| Area | Required result |
| --- | --- |
| External port scan | Only 80 and 443 are reachable on the public interface. |
| Route enumeration | `/public-files` is the only proxied namespace; v1/v2/v3, docs, debug, setup, SSH, and admin routes are 404. The edge upstream is exactly `127.0.0.1:39777`, never Gateway. |
| TLS | Trusted chain and hostname; TLS 1.2/1.3; renewal tested and monitored. |
| Authentication | Missing, malformed, duplicate, wrong, and query-string tokens fail without revealing why. After atomic verifier publication and a controlled restart, the old bearer returns 401 and the new bearer returns 200. |
| Credential isolation | The raw `rc1_` bearer was generated off-host, its only durable operator copy is in the password manager, and the host provisions only the exact versioned verifier through `recasaos-public-file-verifier`; authorized requests still place the bearer transiently in edge and portal memory. `LimitCORE=0` is active. Missing or malformed verifier input and any non-empty legacy `RECASAOS_PUBLIC_FILE_TOKEN_FILE` value fail startup when the portal is enabled. Bidirectional bind-alias and rollback tests fail closed. |
| Process isolation | Issue #25 is resolved with reviewed evidence that the Internet-facing listener and potentially blocking filesystem work cannot inherit or stop the privileged management daemon. The current in-process candidate does not pass this row. |
| Path confinement | Absolute/parent/encoded traversal, hidden names, symlinks, hardlinks, mount points, devices, pipes, and sockets cannot be listed or downloaded. |
| Root filesystem | Startup records the mount ID and allowlisted filesystem type from the pinned root FD. FUSE, network, overlay, ZFS, and unknown roots are rejected before the listener is usable; replacing or remounting the configured pathname does not redirect the live portal away from its original descriptor. |
| Browser boundary | CSP has no inline/eval allowance; the supplied client is designed not to write the bearer to a URL, Referer, history, cookie, Cache API, Web Storage, or IndexedDB, while page, Worker, header, edge, and server request memory remain transient handling boundaries. In stable Chromium, Firefox, and WebKit over real HTTPS, verify storage, DevTools, proxy/application logs, and crash artifacts do not retain it; verify a large download starts without full-body buffering and preserves bytes/filename; replay, another tab, Worker restart, logout, rotation, redirect, and malformed messages fail closed. Record memory measurements and initial Range, retry/resume, and cancellation results. |
| Response handling | GET, HEAD, and one byte range work, including offsets above 4 GiB; multi-range work is rejected; 401/404/416/503 and successful private-file responses retain `no-store` and `nosniff`. A progressing transfer can cross the base write timeout, while idle and below-budget clients are terminated. |
| Client cancellation | After a large response starts, abort the client and verify that the chosen edge promptly closes its loopback upstream request and releases portal download capacity. Test both HTTP/1.1 and HTTP/2 at the public edge when both are enabled. |
| Resource bounds | Oversized directory and request-body tests fail; slow clients do not exhaust all edge connections. Nginx rate/connection limits or the separately reviewed Caddy-fronting limiter are exercised. |
| Logs | No bearer, verifier, query, private host path, file content, cookie, or personal data appears in edge/application logs or crash artifacts. |
| Backups | Share and configuration can be restored to an isolated host with recorded checksums and acceptable RPO/RTO. |

Any failed row blocks public DNS/exposure. Passing repository static tests does
not satisfy this target-host matrix. Retest after every routing, auth, kernel,
proxy, installer, or component change.

## Operational limits

The bearer token is a shared capability, not per-person authorization or MFA.
Use a separate portal/root/token per trust group, rotate tokens regularly, and
remove access immediately when a recipient leaves. Generate every replacement
off-host and publish only its verifier. Replacing the verifier source does not
change the credential already loaded in memory: rotation requires a controlled
restart, then explicit proof that the old bearer returns 401 and the new bearer
returns 200. Even a completed rotation cannot retract bytes already handed to a
browser download manager.
The native browser-stream candidate keeps the bearer header-only; unsupported
browsers are limited to the bounded 32 MiB fallback. Until Issue #20's browser
matrix passes, use a separately reviewed streaming client that can set an
Authorization header for large files.

For upload, sharing links, expiry, audit identities, per-user policy, previews,
or remote administration, use a separately isolated and independently tested
file product. Do not re-enable the privileged v1/v2/v3 file APIs on the public
hostname to obtain those features.

This repository currently supplies a candidate application boundary and
deployment test plan, not a production public-ready package. No host may be
called public-ready until Issues #22, #25, and #26 are resolved with reviewed
evidence, and the acceptance matrix, restore drill, vulnerability gates, and
independent deployment review also pass for the locked component set.
