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

Verifier-only provisioning removes the raw bearer from the server filesystem.
systemd owns the dedicated loopback listener, while its request handler runs in
a separate non-root, socket-activated service whose lifecycle no longer shares
the privileged management daemon. The standalone coordinator delegates
bootstrap, list, open, and read operations to bounded same-binary workers and
retains no readable share file. This is the candidate blocking-I/O boundary, but
[Issue #25](https://github.com/EdmundFu-233/ReCasaOS/issues/25) remains a
production public-readiness blocker until the remaining real FUSE or
remote-backed storage cases and the exact target-host matrix prove the complete
deployment boundary.

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
- at most eight active storage workers, fixed operation deadlines, pidfd-based
  termination, and admission quarantine for killed children that cannot be
  reaped;
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
single-use correlation nonce and a separate 192-bit navigation proof bound to
the exact top-level portal client, relative path, and same-origin file URL for
at most 10 seconds. The page then submits a same-origin top-level POST. Its URL
contains only the non-secret correlation nonce in the fragment; its body
contains only the navigation proof. Neither value is the bearer. Before
consuming the reservation, the Worker requires the exact POST navigation,
form content type, path, URL, nonce, and proof. A copied URL, raw GET, invalid
proof, expired reservation, or replay therefore fails without challenging the
original page, making an authenticated upstream request, or consuming a valid
reservation. This proof avoids relying on navigation client-ID fields whose
behavior is not portable across current browser engines.

After validation, the Worker consumes the reservation atomically, erases the
proof, challenges only the original portal page over a `MessageChannel`,
receives the bearer once, removes the fragment, and makes one clean same-origin
file request with the bearer in the `Authorization` header. Redirects fail,
credentials are omitted, and the
worker requires the exact clean URL, 200/206 status, attachment disposition,
octet-stream type, absent content encoding, an explicit decimal content length,
`no-store`, `nosniff`, and byte-range policy. It then wraps the upstream body in
a one-chunk, backpressure-preserving monitor without calling `blob()`,
`arrayBuffer()`, cloning, or teeing the body. The Worker retains only the active
abort handle and status port until EOF, cancellation, or an error. Forgetting
the token therefore aborts the upstream fetch even after the response has been
handed to the browser, while normal completion releases the page and Worker
state. A restart loses all transient reservations and therefore fails closed.
Invalid controlled navigations receive an empty `204` without
consuming a valid reservation. If the POST reaches the server because the
Worker was replaced or bypassed, its browser-generated navigation metadata also
selects an empty `204`, so the portal document remains in place and access stays
denied. Ordinary non-navigation API clients retain `401`/`405` behavior.

The portal does not publish `Last-Modified` or a strong `ETag` for a file. It
passes a zero modification time to `http.ServeContent`, so a request carrying
`If-Range` cannot resume from a weak or unknown representation and instead
receives the complete current representation with `200`. A plain, single
initial `Range` request still receives `206`. This prevents a same-second file
replacement from splicing a cached prefix onto a new suffix; it does not claim
that transparent retry/resume is supported.

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
redirects, transparent retry/resume, and cancellation. The
current nonce is deliberately one-shot, so a later automatic retry with the
same URL fails closed rather than silently reusing authorization.

The repository also contains a narrower CI smoke test. On an ephemeral
GitHub-hosted Ubuntu 24.04 runner it installs a one-run CA into the system and
NSS trust stores, keeps TLS verification enabled, and exercises the real
portal handler and frontend with the Playwright-bundled Chromium, Firefox, and
WebKit engines. The job receives no production credential and ordinarily
retains no trace, HAR, video, browser profile, or HTML-report artifact. If a
trusted same-repository run stalls during the cross-tab portal navigation
*before either page receives a bearer*, it may retain one narrowly scoped
Playwright trace plus structured page, TLS, and loopback-server diagnostics
for one day. Structured events exclude header and query/fragment values. The
trace can contain ordinary pre-authorization browser request/response headers,
but both the test and an independent pre-upload gate delete or reject any file
containing the `rc1_` bearer format or an `Authorization`,
`Proxy-Authorization`, `Cookie`, or `Set-Cookie` header, or non-empty parsed
cookie metadata. Trace sources, browser profiles, HAR, video, and HTML reports
remain excluded, and untrusted fork PRs cannot upload this bundle. This
failure-only evidence does not exercise the production `NewIsolated`
coordinator, systemd/cgroup sandbox, Caddy/Nginx, public DNS, HSTS, retail
Chrome/Firefox, Safari/iOS, or a target host. Its initial-Range case is limited
to the bundled engines. Its lifecycle cases require an exactly consumed proof
to fail replay without another authorization challenge or upstream request and
require a page logout to terminate an already handed, still-active stream. They
do not prove Worker-process restart, token rotation, transparent retry/resume,
retail-browser behavior, or target-host behavior. Passing them is not
sufficient to close Issue #20 or enable public routing.

If Firefox loses only Playwright's external navigation lifecycle event while
the target document is already loaded, the smoke test continues without a
retry only when every independent proof agrees: the driver remains exactly on
`about:blank`, the in-document URL is the exact HTTPS portal, the pre-auth DOM
is complete and credential-free, the captured main-frame response is a direct
non-Service-Worker `GET` document with status `200`, the Go request delta is
exactly one start and one completion with no active request or server/TLS
error, and a separate trusted TLS 1.3 probe returns `200`. The full cross-tab
authorization and download-reservation assertions still run. Any mismatch
remains a test failure and follows the diagnostic path above.

This verified Firefox state leaves Playwright's locator auto-wait attached to
the stale external navigation lifecycle even though direct in-document
evaluation succeeds. The diagnostic helper therefore repeats the complete
pre-authorization page proof immediately before returning, and the caller
rechecks the exact URL, ready state, secure context, login visibility, hidden
browser panel, and empty token through direct in-document evaluation. Only
that exact verified path bypasses the three equivalent locator checks; all
later cross-tab authorization, Service Worker, request-count, and downloaded
byte assertions are unchanged.

The cancel smoke requires all three engines to report the local download as
canceled to Playwright, and exactly one authorized upstream request to reach a
terminal state within the 40-second test-harness deadline. Chromium and WebKit
must classify that request as canceled; Playwright Firefox may classify it as
canceled or completed. That outcome is consistent with Mozilla
[Bug 1825388](https://bugzilla.mozilla.org/show_bug.cgi?id=1825388), which
covers a related Service Worker cancellation path, but does not establish the
same root cause. The exception is only a no-retained-slot assertion; it is not
Firefox cancellation evidence.

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
Completing this credential migration and staging the independent service does
not make a host public-ready; Issue #25's real hung-storage evidence and the
complete target-host acceptance matrix remain open.

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
`RESOLVE_NO_XDEV` still rejects nested mount crossings. The packaged service
uses a recursive read-only bind so host submounts remain visible as distinct
mounts and are rejected; a non-recursive bind is forbidden because it could
reveal underlying files that the host submount normally covers. These checks
occur before a usable Portal or download-slot pool is returned. They prevent a
known network/FUSE root from entering the request path, but they do not make local
kernel or block-device I/O interruptible: a bad disk, remote block device, or
kernel fault can still block a worker. Bootstrap has a 12-second coordinator
deadline, and the packaged `Type=notify` service has a 30-second startup
deadline, but those deadlines cannot physically complete a child already stuck
in uninterruptible kernel sleep. The parent kills timed-out workers through an
atomically acquired pidfd, quarantines an unreaped child, stops new admission
once four such children are retained, and relies on the unit-wide `TasksMax=256`,
`MemoryMax=512M`, disabled swap, and `KillMode=control-group` as final bounds.
If pidfd signaling returns an error other than ESRCH, the coordinator closes
all later worker admission and keeps the active slot until the child is reaped;
it never risks signaling a reused numeric PID.
Up to eight request workers may already be active when three older quarantined
workers exist, so one coordinator generation can retain eleven children. Host
storage and the mount namespace remain trusted operator boundaries. This is a
staged control for
[Issue #22](https://github.com/EdmundFu-233/ReCasaOS/issues/22), not proof that
the isolated portal process can safely contain every blocking storage failure.
The bounded worker protocol is implemented. The Debian 11 QEMU qualification
job additionally creates a dedicated 256 MiB loop-backed ext4 filesystem behind
a device-mapper linear target entirely inside the disposable guest. After the
production portal has pinned that root, the job drops the guest's clean caches
and suspends only that test mapping with `--nolockfs --noflush`. Four concurrent
authenticated directory operations must enter real kernel D-state. Their fixed
operation deadlines must each return 503 with `Retry-After`, leave the exact
pidfd-signalled child in D-state, and trip the four-worker quarantine threshold
without creating a fifth child. The job records live unit task and memory
headroom, proves that the independent management sentinel is unchanged, and
requests a non-blocking portal restart. systemd must remain in deactivation
behind the four reparented D-state children until an explicit mapper resume;
after that operator action the exact old workers must disappear, a new portal
invocation must pass the isolation checks, and the original file bytes must be
readable. Cleanup always attempts the exact mapper resume before stopping any
unit, then unmounts and removes only the recorded mapping and loop device.

This is real recoverable device-mapper D-state evidence, not proof for FUSE,
NBD/iSCSI, a permanently failed device, every kernel fault, or the exact target
host. Those separate gates remain required by
[Issue #25](https://github.com/EdmundFu-233/ReCasaOS/issues/25).
The hosted systemd job uses the production build for activation, sandbox and
API smoke checks. For deterministic worker saturation and coordinator cleanup,
it temporarily swaps in a non-release CI-tagged binary whose worker for the
exact synthetic `worker-load.bin` fixture stops itself after its first
successful read. Closing the clients then exercises coordinator pidfd
cancellation, and a main-process crash exercises systemd control-group cleanup.
That tagged synchronization is not an uninterruptible-storage simulation; the
separate device-mapper phase above supplies the real D-state case without
shipping any test hook in the production binary.

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

### Hold the verifier until the clean-host gate

Keep the transferred verifier at its authenticated transfer destination; do not
create or overwrite `/etc/recasaos` yet. Section 2 first proves that the target
has no prior candidate payload, account, share, unit, or verifier, then
validates and publishes the verifier as part of the staged installation. If any
of that state already exists, stop and use a separately reviewed upgrade or
removal procedure.

The verifier loader requires the exact versioned line, a stable single-link
regular file, service-safe ownership, and restrictive permissions. It rejects
unexpected whitespace, uppercase or non-hexadecimal digest text, links, and
ambiguous legacy input.

Remove every `RECASAOS_PUBLIC_FILE_*` setting from environment files, service
drop-ins, container definitions, and process-manager settings before restart.
The standalone binary has no environment configuration fallback and rejects
every non-empty legacy setting before it loads the activation descriptor.
During a first migration, stop public routing, remove the legacy raw-token file
from the host, and do not use that legacy path as rollback. Until those steps
finish, the host is in a maintenance migration state and is not public-ready.

## 2. Stage the isolated service with public routing disabled

The standalone service requires Linux 5.8 or newer, systemd 247 or newer, and
the unified cgroup v2 hierarchy with effective `memory` and `pids` controllers.
`MemorySwapMax=0` is not an enforceable boundary on cgroup v1, so both the
service and socket fail their conditions before activation unless the required
cgroup v2 controller files exist. The service unit then exposes only its own
`memory.max`, `memory.swap.max`, and `pids.max` files as three separate
read-only mounts below `/run/recasaos-cgroup` inside the jail. Before loading
the verifier, the process requires exact `/system.slice/recasaos-public-files.service`
membership and cross-checks each open file's mount ID against `/proc/self/mountinfo`,
its exact service-cgroup source, the cgroup2 filesystem, the read-only mount
flag, and the reviewed value. `LoadCredential=` is available at the systemd
baseline. The packaged unit intentionally uses
`${CREDENTIALS_DIRECTORY}` in `ExecStart`; the shorter `%d`
credential-directory specifier was added later and must not be substituted
while systemd 247 remains supported. The staging checker accommodates
`systemd-analyze`'s host-path executable check with a disposable unit copy; the
production `ExecStart` remains byte-locked and the live activation gate proves
the executable inside `RootDirectory=`. systemd 247 sets `NOTIFY_SOCKET` but,
unlike systemd 248 and newer, does not automatically bind that socket into a
service root. The packaged unit therefore declares the same non-recursive,
read-only notification-socket bind explicitly, and the live test verifies its
socket identity and mount flags before accepting the isolation result. The
minimal root also pre-creates a root-owned `/run/systemd` directory that is not
writable by the service identity, plus an empty bind target, so the service's
restrictive `UMask=0077` cannot make a dynamically created parent
untraversable on systemd 247. Both the service and socket require a non-empty
verifier and independently reject a
verifier-path symlink before
their initial activation, so either condition prevents the socket from binding
when it is already unsafe at that point. A non-empty malformed verifier, or a
verifier changed after socket activation, instead makes service bootstrap and
readiness fail but does not automatically unbind systemd's existing socket.
Keep edge routing and health publication disabled, stop both units, reprovision
the verifier, and repeat the activation tests before treating that listener as
usable.

> **Compatibility qualification status:** CI retains the unprivileged
> parser/semantic check and separately boots a pristine, ephemeral Debian 11
> guest with systemd 247 as PID 1 and unified cgroup v2. The latter job pins an
> official Debian generic cloud image and its SHA-512 digest, uses QEMU TCG
> software emulation without a host mount, device, or KVM dependency, transfers
> only an archive of the clean exact commit plus the pinned Go toolchain, and
> reruns the live isolation suite inside the guest. It exercises the three
> read-only effective-limit binds, readiness, restart, cancellation, cleanup,
> worker capacity, resource headroom, and the isolated recoverable
> device-mapper D-state scenario described above. Its eight-worker aggregate
> orchestration window is 30 seconds under QEMU TCG, versus 15 seconds on the
> native hosted runner. The eight holders are launched without serializing
> each admission, then every client, stopped worker, and exact event chain must
> be present. Journal visibility has a separate 10-second evidence-only bound;
> one root-only `/proc` snapshot checks all eight immutable process identities,
> address-space limits, bearer absence, memory ownership, descriptor flags, and
> listener non-inheritance without serial observer overhead. This does not
> change the service write timeout, worker IPC deadlines, cgroup limits, or
> cleanup requirements. Because systemd 247 does
> not expose
> `MemoryPeak`, a separately tested 10 ms guest-side sampler records the peak
> `memory.current`; newer managers must still expose a numeric `MemoryPeak`
> which is at least the sampled peak. A skipped or failed VM job is not
> compatibility evidence.
> Keep Issue #25 open, and do not enable public routing merely because this VM
> job passes: real FUSE or remote-backed block behavior, permanent-failure
> handling, and the exact target-host recovery matrix remain separate release
> gates.
> Debian 11 is a compatibility target, not a recommended new deployment
> platform.

Check the actual target before installing anything:

```bash
(
  set -euo pipefail
  systemd_version="$(systemd --version | awk 'NR == 1 { print $2 }')"
  [[ "$systemd_version" =~ ^[0-9]+$ ]]
  (( systemd_version >= 247 ))
  manager_version="$(sudo systemctl show --property=Version --value)"
  [[ "$manager_version" =~ ^([0-9]+) ]]
  manager_major="${BASH_REMATCH[1]}"
  (( manager_major >= 247 ))
  kernel_version="$(uname -r)"
  [[ "$kernel_version" =~ ^([0-9]+)\.([0-9]+) ]]
  kernel_major="${BASH_REMATCH[1]}"
  kernel_minor="${BASH_REMATCH[2]}"
  (( kernel_major > 5 || (kernel_major == 5 && kernel_minor >= 8) ))
  [[ "$(stat -fc %T /sys/fs/cgroup)" == cgroup2fs ]]
  [[ -f /sys/fs/cgroup/cgroup.controllers ]]
  for controller_file in memory.max memory.swap.max pids.max
  do
    [[ -f "/sys/fs/cgroup/system.slice/$controller_file" ]]
  done
  controllers=" $(< /sys/fs/cgroup/cgroup.controllers) "
  [[ "$controllers" == *" memory "* ]]
  [[ "$controllers" == *" pids "* ]]
  printf \
    'reviewed prerequisites: systemd-binary=%s manager=%s kernel=%s cgroup=v2\n' \
    "$systemd_version" "$manager_version" "$kernel_version"
)
```

This repository still disables binary releases until the component BOM,
installer, clean upgrade, and rollback path are locked. Do not replace a live
CasaOS installation with an ad hoc local build. The commands below describe the
candidate artifact layout for an isolated test host or reviewed package build;
keep public DNS and the TLS edge disabled throughout staging.

### Retire the privileged-daemon integration

Older candidates installed
`/etc/systemd/system/casaos.service.d/recasaos-public-files-verifier.conf`.
That drop-in must not remain active. Quarantine that exact file in a root-only
operator workspace, reload systemd, and upgrade/restart the management daemon
through the reviewed ReCasaOS package procedure. Never use the old drop-in as a
rollback path.

Before continuing, both of these checks must exit zero without printing
environment values:

```bash
(
  set -euo pipefail
  old_dropin=/etc/systemd/system/casaos.service.d/recasaos-public-files-verifier.conf
  ! sudo test -e "$old_dropin"
  ! sudo test -L "$old_dropin"
  sudo systemctl cat casaos.service >/dev/null
  if sudo systemctl cat casaos.service |
    grep -q 'RECASAOS_PUBLIC_FILE_'
  then
    printf '%s\n' \
      'casaos.service still contains legacy public-file environment settings' >&2
    exit 1
  fi
)
```

The root daemon must retain only the Gateway 404 tombstone for `/public-files`;
it must not import `pkg/publicfiles`, read a portal credential, or bind port
39777. The repository's
`.github/scripts/check-public-files-service-boundary.sh` enforces that
dependency and source boundary.

### Install the candidate payload

Build the public binary as an unprivileged user. It is static and deliberately
not UPX-compressed because the service enables `MemoryDenyWriteExecute=yes`.

```bash
make build-public-files
```

This is a clean-host staging procedure, not an upgrade procedure. Before its
first mutation, fail if any candidate payload, account, share, unit override,
or higher-priority sysusers/tmpfiles configuration already exists:

```bash
(
  set -euo pipefail
  manager_version="$(sudo systemctl show --property=Version --value)"
  test -n "$manager_version"

  require_absent_unit() {
    local unit="$1"
    local load_state active_state enabled_state
    local active_status=0 enabled_status=0

    load_state="$(
      sudo systemctl show --property=LoadState --value "$unit"
    )"
    if test "$load_state" != not-found; then
      printf 'refusing existing or unreadable unit state: %s (%s)\n' \
        "$unit" "$load_state" >&2
      exit 1
    fi

    active_state="$(sudo systemctl is-active "$unit" 2>/dev/null)" ||
      active_status=$?
    if test "$active_status" -eq 0 ||
      { test "$active_state" != inactive &&
        test "$active_state" != unknown; }
    then
      printf 'refusing ambiguous active state: %s (%s/%s)\n' \
        "$unit" "$active_state" "$active_status" >&2
      exit 1
    fi

    enabled_state="$(sudo systemctl is-enabled "$unit" 2>/dev/null)" ||
      enabled_status=$?
    if test "$enabled_status" -eq 0 || test "$enabled_state" != not-found; then
      printf 'refusing ambiguous enablement state: %s (%s/%s)\n' \
        "$unit" "$enabled_state" "$enabled_status" >&2
      exit 1
    fi
  }

  for target in \
    /usr/lib/recasaos-public-files \
    /etc/recasaos \
    /usr/lib/systemd/system/recasaos-public-files.service \
    /usr/lib/systemd/system/recasaos-public-files.service.d \
    /usr/lib/systemd/system/recasaos-public-files.socket \
    /usr/lib/systemd/system/recasaos-public-files.socket.d \
    /usr/local/lib/systemd/system/recasaos-public-files.service \
    /usr/local/lib/systemd/system/recasaos-public-files.service.d \
    /usr/local/lib/systemd/system/recasaos-public-files.socket \
    /usr/local/lib/systemd/system/recasaos-public-files.socket.d \
    /lib/systemd/system/recasaos-public-files.service \
    /lib/systemd/system/recasaos-public-files.service.d \
    /lib/systemd/system/recasaos-public-files.socket \
    /lib/systemd/system/recasaos-public-files.socket.d \
    /usr/lib/sysusers.d/recasaos-public-files.conf \
    /usr/lib/tmpfiles.d/recasaos-public-files.conf \
    /etc/systemd/system/recasaos-public-files.service \
    /etc/systemd/system/recasaos-public-files.service.d \
    /etc/systemd/system/recasaos-public-files.socket \
    /etc/systemd/system/recasaos-public-files.socket.d \
    /run/systemd/system/recasaos-public-files.service \
    /run/systemd/system/recasaos-public-files.service.d \
    /run/systemd/system/recasaos-public-files.socket \
    /run/systemd/system/recasaos-public-files.socket.d \
    /etc/sysusers.d/recasaos-public-files.conf \
    /run/sysusers.d/recasaos-public-files.conf \
    /usr/local/lib/sysusers.d/recasaos-public-files.conf \
    /etc/tmpfiles.d/recasaos-public-files.conf \
    /run/tmpfiles.d/recasaos-public-files.conf \
    /usr/local/lib/tmpfiles.d/recasaos-public-files.conf \
    /srv/recasaos-public
  do
    if sudo test -e "$target" || sudo test -L "$target"; then
      printf 'refusing to overwrite existing candidate state: %s\n' \
        "$target" >&2
      exit 1
    fi
  done
  ! getent passwd recasaos-public >/dev/null
  ! getent group recasaos-public >/dev/null
  require_absent_unit recasaos-public-files.service
  require_absent_unit recasaos-public-files.socket
  candidate_binary=build/sysroot/usr/lib/recasaos-public-files/rootfs/usr/bin/recasaos-public-files
  test -x "$candidate_binary"
  test ! -L "$candidate_binary"
  file "$candidate_binary" | grep -q 'statically linked'
  sudo test -f /path/to/transferred.verifier
  ! sudo test -L /path/to/transferred.verifier
  test "$(sudo stat -c '%s' /path/to/transferred.verifier)" -eq 100
  sudo env LC_ALL=C grep -Eq \
    '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' \
    /path/to/transferred.verifier
  sh deploy/systemd/check-public-files-units.sh .
)
```

If this gate finds prior candidate state, stop and use a separately reviewed
upgrade or removal procedure; do not delete or overwrite it from this guide.
On a clean isolated test host, a reviewed package installs the binary and
metadata at the following exact paths:

```bash
(
  set -euo pipefail
  verify_verifier_file() {
    test "$(sudo stat -c '%s' "$1")" -eq 100
    sudo env LC_ALL=C grep -Eq \
      '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' "$1"
  }

  sudo install -D -o root -g root -m 0755 \
    build/sysroot/usr/lib/recasaos-public-files/rootfs/usr/bin/recasaos-public-files \
    /usr/lib/recasaos-public-files/rootfs/usr/bin/recasaos-public-files
  sudo install -D -o root -g root -m 0644 \
    build/sysroot/usr/lib/systemd/system/recasaos-public-files.service \
    /usr/lib/systemd/system/recasaos-public-files.service
  sudo install -D -o root -g root -m 0644 \
    build/sysroot/usr/lib/systemd/system/recasaos-public-files.socket \
    /usr/lib/systemd/system/recasaos-public-files.socket
  sudo install -D -o root -g root -m 0644 \
    build/sysroot/usr/lib/sysusers.d/recasaos-public-files.conf \
    /usr/lib/sysusers.d/recasaos-public-files.conf
  sudo install -D -o root -g root -m 0644 \
    build/sysroot/usr/lib/tmpfiles.d/recasaos-public-files.conf \
    /usr/lib/tmpfiles.d/recasaos-public-files.conf

  sudo systemd-sysusers /usr/lib/sysusers.d/recasaos-public-files.conf
  sudo systemd-tmpfiles --create \
    /usr/lib/tmpfiles.d/recasaos-public-files.conf

  verify_verifier_file /path/to/transferred.verifier
  sudo install -d -o root -g root -m 0700 /etc/recasaos
  sudo install -o root -g root -m 0600 \
    /path/to/transferred.verifier \
    /etc/recasaos/public-file.verifier.next
  verify_verifier_file /etc/recasaos/public-file.verifier.next
  sudo test ! -e /etc/recasaos/public-file.verifier
  sudo test ! -L /etc/recasaos/public-file.verifier
  sudo mv -f -- \
    /etc/recasaos/public-file.verifier.next \
    /etc/recasaos/public-file.verifier

  sudo systemctl daemon-reload
  sudo env \
    RECASAOS_SYSTEMD_VERIFY=1 \
    RECASAOS_SYSTEMD_LIVE_VERIFY=1 \
    sh deploy/systemd/check-public-files-units.sh .
)
```

If any command in this staging block fails, keep the public edge and socket
disabled. Do not rerun it blindly or delete partial paths; inventory the exact
state and use a separately reviewed removal or upgrade procedure.

The live verification compares every installed payload with the reviewed
checkout, rejects higher-priority unit fragments and drop-ins, requires the
socket to remain disabled and inactive, and rechecks the verifier, share, and
binary metadata. The same fail-fast block publishes the transferred verifier
only after the complete clean-host gate passes.

The system account receives a host-specific numeric UID/GID; the unit never
hard-codes one. The share directory is `root:recasaos-public` mode `0750`.
Approve each published file explicitly and make it a single-link regular file
readable by that group, normally `root:recasaos-public` mode `0640`. Do not
recursively change ownership or permissions on an existing data tree and do
not make the share world-readable.

The socket is intentionally not enabled by the package. Start it only while
the public edge remains disabled:

```bash
(
  set -euo pipefail
  sudo systemctl start recasaos-public-files.socket
  status="$(
    curl -q -sS -o /dev/null -w '%{http_code}' \
      http://127.0.0.1:39777/public-files/
  )"
  test "$status" = 200
  sudo systemctl is-active --quiet recasaos-public-files.socket
  sudo systemctl is-active --quiet recasaos-public-files.service
)
```

Starting the service directly without its socket fails closed: the binary
requires exactly one inherited descriptor named `public-files`, verifies that
it is a TCP listener at the configured literal-loopback address, and never
calls `net.Listen`. It also refuses root UID/GID, supplementary privilege
groups, capabilities, a permissive umask, missing `NoNewPrivileges`, missing
seccomp, every old `RECASAOS_PUBLIC_FILE_*` environment setting, and any
unknown or incomplete CLI.

The service uses `Type=notify` with `NotifyAccess=main`. It sends `READY=1` only
after the bootstrap worker has returned a validated verifier digest and pinned
root and the HTTP server has entered the inherited listener's accept loop.
Cancellation, server failure, or notification failure before readiness stops
the server and closes the portal rather than publishing a false-ready state.
The coordinator's per-process `LimitNOFILE=512`, each worker's smaller
per-process descriptor limit, and the unit-wide `TasksMax=256`,
`MemoryMax=512M`, `MemorySwapMax=0`, and `KillMode=control-group` are part of
the reviewed worker-containment boundary; they do not replace the target-host
hung-storage tests.

The packaged service uses a minimal `RootDirectory=`, exposes the share only as
the read-only `/srv/public`, exposes the system manager's notification socket
as one non-recursive read-only bind needed for `READY=1`, exposes only the three
read-only effective cgroup limit files described above, imports the verifier
through `LoadCredential=`, has a private network namespace, permits creation of
only AF_UNIX sockets, and has an empty capability bounding set. With
`NotifyAccess=main`, PID 1 accepts readiness messages only from the main
service process. Its `InaccessiblePaths=` and
`ReadOnlyPaths=` entries use systemd's `+` prefix so the masks apply inside
`RootDirectory=` rather than to the host root: jail `/sys` is mandatory and
inaccessible, `/dev/shm` is inaccessible when present, and jail `/tmp` and
`/var/tmp` are read-only. It has no dependency on `casaos.service`. A portal
startup failure, crash, restart limit, or controlled stop must leave the
management daemon PID and health unchanged.

On ACL-capable systems, systemd keeps the runtime credential owned by
`root:root` and grants only the service UID named-user read access. Linux then
reports mode `0440` because the group mode bits represent the ACL mask, not
ordinary group access. The portal accepts only that exact five-entry ACL;
ordinary group-readable `0440`, extra ACL principals, and writable ACL entries
fail startup. The older read-only-store fallback remains a service-owned
`0400` file without an extended ACL. Descriptor metadata is checked on each
`O_PATH` pin. ACL bytes are checked on exact readable reopens before any
verifier content is read, again after reading, and on a fresh readable reopen
of the final configured path; any observed drift fails startup. The packaged
systemd credential store is independently required to be a read-only mount.

Do not enable the socket at boot or restore the public edge until every
applicable acceptance row below passes on the exact target host. A safe rollback
first removes or blocks the edge route, then independently attempts both
systemd shutdown operations. The two `false` commands are deliberate
fail-closed placeholders: replace them with the reviewed, synchronous edge
withdrawal and independent route-closed verification commands for the actual
deployment. Running the template unchanged still attempts both systemd
operations but exits nonzero:

```bash
(
  set -uo pipefail
  rollback_status=0

  false || rollback_status=1 # Replace with edge withdrawal/reload.
  false || rollback_status=1 # Replace with independent route-closed proof.

  sudo systemctl disable --now recasaos-public-files.socket ||
    rollback_status=1
  sudo systemctl stop recasaos-public-files.service ||
    rollback_status=1

  socket_state="$(
    sudo systemctl show --property=ActiveState --value \
      recasaos-public-files.socket
  )" || rollback_status=1
  service_state="$(
    sudo systemctl show --property=ActiveState --value \
      recasaos-public-files.service
  )" || rollback_status=1
  test "${socket_state:-}" = inactive || rollback_status=1
  test "${service_state:-}" = inactive || rollback_status=1

  if test "$rollback_status" -ne 0; then
    printf '%s\n' \
      'rollback incomplete; keep routing withdrawn and investigate every failed step' >&2
  fi
  exit "$rollback_status"
)
```

Rollback must not restore the retired root-daemon drop-in. The process split
prevents public-service lifecycle failures from stopping the privileged
management daemon, and the standalone coordinator delegates share filesystem
operations to bounded disposable workers. Stopping the coordinator aborts
active workers, and `KillMode=control-group` cleans normally killable
descendants; a worker stuck in uninterruptible D-state can nevertheless outlive
the coordinator or a stop attempt. Issue #25 remains open until exact-head
Linux and hostile-storage tests prove timeout, quarantine, cgroup cleanup,
restart, cancellation, operator recovery, and resource-headroom behavior.

### Rotate, verify, and roll back

Generate each replacement bearer and verifier on the independent administrator
workstation exactly as in section 1. Keep both the previous and pending raw
bearers in the password manager until verification finishes. Transfer only the
pending verifier to the host.

The production hostname's portal route must remain withdrawn for the complete
rotation and rollback window. Before changing the verifier, prepare a separate,
temporary validation hostname such as `rotation-check.files.example.net` with
a publicly trusted certificate, the same portal-only route/upstream controls,
and an exact source-IP allowlist containing only the unrelated test client.
All other sources and every non-portal route must be denied. Protect this route
with a short recorded automatic expiry as well as an explicit removal command,
and verify the deny from a second, non-allowlisted source. Do not use the
production hostname as this validation endpoint.

Before publication, retain a root-only rollback copy of the current strict
verifier. Stage the pending verifier in the same directory, then publish it
with one rename and restart only `recasaos-public-files.service` so systemd
creates a new credential instance. The management daemon must not be restarted
by this procedure:

```bash
(
  set -euo pipefail
  verify_verifier_file() {
    test "$(sudo stat -c '%s' "$1")" -eq 100
    sudo env LC_ALL=C grep -Eq \
      '^recasaos-public-verifier-v1:sha256:[0-9a-f]{64}$' "$1"
  }

  for rotation_artifact in \
    /etc/recasaos/public-file.verifier.rollback \
    /etc/recasaos/public-file.verifier.next \
    /etc/recasaos/public-file.verifier.rollback.next
  do
    if sudo test -e "$rotation_artifact" ||
      sudo test -L "$rotation_artifact"
    then
      printf 'refusing to overwrite retained rotation evidence: %s\n' \
        "$rotation_artifact" >&2
      exit 1
    fi
  done

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
  sudo systemctl restart recasaos-public-files.service
  sudo systemctl is-active --quiet recasaos-public-files.service
)
```

Changing the source verifier without a successful restart does not rotate the
credential already loaded by the running process. Enable the temporary
source-allowlisted validation route, then from that unrelated allowlisted
client require **old = 401** and **new = 200**. The fail-fast template below
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
        'https://rotation-check.files.example.net/public-files/api/list?path='
  )"
  new_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$new_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://rotation-check.files.example.net/public-files/api/list?path='
  )"
  test "$old_status" = 401
  test "$new_status" = 200
  unset old_bearer new_bearer old_status new_status
)
```

Immediately after this gate exits, whether successfully or not, remove the
temporary validation route, reload the edge, and prove from the same client that
the validation hostname no longer reaches the portal. The gate is incomplete
until that teardown proof is recorded.

If restart or either assertion fails, first complete that validation-route
teardown. The production route is already withdrawn. Restore the previous strict
verifier with another same-directory rename, restart, and prove the inverse
result—old bearer 200, pending bearer 401—before restoring any production
routing:

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
  sudo systemctl reset-failed recasaos-public-files.service
  sudo systemctl restart recasaos-public-files.service
  sudo systemctl is-active --quiet recasaos-public-files.service
)
```

For this inverse test, re-enable a fresh instance of the same temporary,
source-allowlisted validation route, then run this separate gate from the
allowlisted unrelated client. As above, replace both `false` commands with the
reviewed password-manager retrieval commands:

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
        'https://rotation-check.files.example.net/public-files/api/list?path='
  )"
  new_status="$(
    builtin printf 'Authorization: Bearer %s\n' "$new_bearer" |
      command curl -q -sS -o /dev/null -w '%{http_code}' -H @- \
        'https://rotation-check.files.example.net/public-files/api/list?path='
  )"
  test "$old_status" = 200
  test "$new_status" = 401
  unset old_bearer new_bearer old_status new_status
)
```

Immediately remove and externally verify removal of the temporary validation
route after this inverse gate, including on failure. Never leave that route
available while investigating a failed rollback.

After a successful rotation, remove the rollback verifier according to the
recorded change procedure and retire the old bearer from the password manager.
A first migration from the rejected raw-token configuration has no supported
raw-token rollback: leave the portal disabled if verifier startup or
authentication fails.

## 3. Install a portal-only TLS edge

Choose one example:

- `deploy/caddy/Caddyfile.example` requires stock Caddy 2.11.4 or newer;
- `deploy/nginx/recasaos.conf.example` is intended for a patched Nginx `http`
  context and uses the portable `listen ... ssl http2` syntax supported by the
  Ubuntu 24.04 Nginx 1.24 package as well as newer releases.

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
6. Keep the no-query access-log format and the supplied runtime-error control:
   Caddy deletes `request>uri` from its default runtime logger, while each
   public Nginx server discards its request-scoped error log. Authorization
   belongs in the header, but query strings can still contain sensitive
   filenames. Access-log formatting alone does not prove runtime errors are
   query-free.
7. Keep the final 404 deny and the 1 MiB request-body ceiling. Portal downloads
   are responses, so large files do not require a large request limit.
8. Keep the edge proxy on a currently supported, fully patched release. The
   Caddy minimum is a security boundary, not permission to defer later patches.

The Nginx example includes explicit default servers for the documented public
addresses. An unknown plaintext `Host` receives `444`, and an unknown or
missing TLS SNI is rejected during the handshake with
`ssl_reject_handshake on`. A valid SNI paired with an unrelated HTTP `Host`
also receives `444`; neither default server has a location or upstream.
Keep these defaults when replacing the documentation addresses. They prevent
direct-IP, unrelated-host, and no-SNI traffic from selecting the portal vhost;
they do not replace certificate hostname validation or the external port and
firewall checks below.

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

By default, both Caddy and Nginx runtime error records may attach the request
URI, including its query, when an upstream, timeout, routing, or TLS error
occurs. The supplied templates add candidate controls for that separate sink:
Caddy's global runtime-log filter deletes `request>uri`, and each public Nginx
server sends its error log to `/dev/null` while retaining the query-free access
log and requiring out-of-band health/metrics. Before a host can be public-ready,
validate that filter or disable/drop behavior on the exact proxy version, then
inject upstream resets, timeouts, bad responses, client aborts, and malformed
requests and inspect every edge, journal, application, and crash sink. If the
target versions cannot prevent or reliably discard URI/query-bearing runtime
records, public exposure remains blocked; do not claim the template text or
access-log format alone closes this boundary.

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
| Credential isolation | The raw `rc1_` bearer was generated off-host, its only durable operator copy is in the password manager, and the host provisions only the exact versioned verifier through `recasaos-public-file-verifier`; authorized requests still place the bearer transiently in edge and portal memory. `LimitCORE=0` is active. Missing or malformed verifier input and every non-empty legacy `RECASAOS_PUBLIC_FILE_*` environment setting fail startup. Bidirectional bind-alias and rollback tests fail closed. |
| Process isolation | systemd owns the Internet-facing loopback socket; the coordinator and workers run under the dedicated non-root `recasaos-public` identity, have no capability or CasaOS-service dependency, cannot create IP sockets, see only the minimal root, read-only share, credential, and three read-only effective cgroup limit files, and can fail/restart without changing the management daemon PID or health. Before loading the credential, the coordinator proves exact service cgroup membership and the source, mount identity, filesystem, read-only flag, and value of all three limit files. It becomes nondumpable; its retained storage and authentication state is limited to the verifier digest, an `O_PATH` root descriptor, fixed mount metadata, and bounded worker-manager state. It reports readiness only after bootstrap and HTTP accept. Bootstrap, list, open, classification, and read run in same-binary workers which inherit neither the AF_INET listener nor raw bearer. At most eight workers are active. Pre-response overload and list/open timeout return 503 with `Retry-After`; a mid-stream read timeout aborts the response connection because its success headers are already committed. Pidfd cancellation and `KillMode=control-group` clean normally killable children. A non-ESRCH pidfd signaling error closes later admission without a numeric-PID fallback. The repository's isolated Debian/QEMU job must prove the recoverable device-mapper D-state case, but this row and Issue #25 remain open until FUSE or remote-backed behavior and the exact target host prove the same admission, resource, restart, and recovery bounds. |
| Platform floor | The exact release candidate passes the `Debian 11 systemd 247 PID1 VM` job under PID 1 on a pristine, ephemeral Debian 11/systemd 247 host with Linux 5.8 or newer and unified cgroup v2. Record the exact commit and image digest, manager and kernel versions, the three cgroup-control-file mount identities, cgroup2/read-only provenance, effective values, readiness, restart, cancellation, cleanup, and version-appropriate resource-headroom evidence. A skipped job, Ubuntu 24.04-only, parser-only, or ordinary-container evidence does not satisfy this row. |
| Path confinement | Absolute/parent/encoded traversal, hidden names, symlinks, hardlinks, mount points, devices, pipes, and sockets cannot be listed or downloaded. |
| Root filesystem | Startup records the mount ID and allowlisted filesystem type from the pinned root FD. FUSE, network, overlay, ZFS, and unknown roots are rejected before the listener is usable; replacing or remounting the configured pathname does not redirect the live portal away from its original descriptor. |
| Browser boundary | CSP has no inline/eval allowance; the supplied client is designed not to write the bearer to a URL, Referer, history, cookie, Cache API, Web Storage, or IndexedDB, while page, Worker, header, edge, and server request memory remain transient handling boundaries. In stable Chromium, Firefox, and WebKit over real HTTPS, verify storage, DevTools, proxy/application logs, and crash artifacts do not retain it; verify a large download starts without full-body buffering and preserves bytes/filename; replay, another tab, Worker restart, logout, rotation, redirect, and malformed messages fail closed. Record memory measurements and initial Range, retry/resume, and cancellation results. |
| Response handling | GET, HEAD, and one byte range work, including offsets above 4 GiB; multi-range work is rejected; 401/404/416/503 and successful private-file responses retain `no-store` and `nosniff`. A progressing transfer can cross the base write timeout, while idle and below-budget clients are terminated. |
| Client cancellation | After a large response starts, abort the client and verify that the chosen edge promptly closes its loopback upstream request and releases portal download capacity. Test both HTTP/1.1 and HTTP/2 at the public edge when both are enabled. |
| Resource bounds | Eight concurrent storage workers succeed while a ninth request returns 503 with `Retry-After`; `TasksCurrent` and `MemoryCurrent` remain below the reviewed unit headroom. Record `MemoryPeak` when the manager exposes it; systemd 247 instead requires separately reviewed guest-side peak sampling or equivalent version-appropriate evidence, and the missing property is not itself a pass. Workers expose neither the AF_INET listener nor raw bearer, all non-stdio descriptors are close-on-exec, and normally killable workers are reaped after cancellation and coordinator SIGKILL. Injected pidfd-signaling failure must close admission and retain capacity until reap. The isolated recoverable device-mapper D-state case must prove the four-worker quarantine admission threshold, `TasksMax=256`, `MemoryMax=512M`, `MemorySwapMax=0`, pending restart behavior, and explicit-resume recovery. Real FUSE or remote-backed and permanent-failure cases must reproduce the relevant bounds before public exposure. `LimitNOFILE` and worker RLIMITs are per-process rather than an aggregate cgroup FD cap. Oversized directory and request-body tests fail; Nginx rate/connection limits or the separately reviewed Caddy-fronting limiter are exercised. |
| Logs | No bearer, verifier, query, private host path, file content, cookie, or personal data appears in edge/application logs or crash artifacts. Because Caddy/Nginx runtime errors may include the URI/query independently of access-log formatting, an exact-version filter or reviewed disable/drop policy is active and fault injection proves upstream failures, timeouts, aborts, malformed requests, and TLS/routing errors remain query-free in every collected sink. Without that evidence this row fails. |
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
called public-ready until Issues #22 and #25 are resolved with reviewed
evidence, Issue #20's browser matrix is complete, and the acceptance matrix,
restore drill, vulnerability gates, and independent deployment review also
pass for the locked component set.
