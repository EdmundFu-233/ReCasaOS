# ReCasaOS threat model

Status: living document for the current root repository. It describes security
boundaries and release gates; it is not a certification. **The current full
stack has not completed the application-level work and independent review
needed to be called safe for unrestricted public administration.**

## Security objectives

- Only an authenticated, authorized user can discover, read, upload, modify,
  share, or delete files and storage configuration.
- Internet clients cannot reach the Gateway, root service, daemon control
  sockets, databases, or management endpoints except through the approved TLS
  edge and route policy.
- A compromised browser session, file, integration, or low-privilege component
  cannot silently become host administrator.
- Secrets and bearer tokens do not appear in repositories, URLs shared with
  third parties, access logs, crash reports, or backups without equivalent
  protection.
- Updates and generated code are reproducible from reviewed, immutable inputs;
  backup and rollback paths are tested before an upgrade is promoted.

Availability matters, but confidentiality and integrity take precedence: rate
limits or fail-closed routing may reject legitimate traffic during an attack.

## Assets and trust zones

High-value assets include user files and mounted volumes, shares and cloud
credentials, authentication keys/tokens, root-service configuration and SQLite
state, system control privileges, update keys/artifacts, logs, and backups.

The intended zones are:

1. **Untrusted Internet** — arbitrary clients and automated scanners.
2. **TLS edge** — the only public HTTP ingress; terminates TLS, overwrites
   forwarding headers, applies body limits and, where configured, connection
   and request-rate limits, and blocks explicitly private paths. The Nginx
   example includes those limits; the Caddy example requires a separate,
   reviewed rate-limiting edge/WAF.
3. **Read-only public file portal** — an opt-in capability with a pinned
   server-side root, separate header-only bearer token, and Linux `openat2`
   confinement. A systemd socket owns the dedicated literal-loopback listener,
   defaulting to `127.0.0.1:39777`, and passes it to a separate non-root process
   with a private network namespace and minimal read-only root filesystem. Only
   that long-lived coordinator receives the listener and raw request bearer;
   same-binary storage workers inherit neither and receive only a private
   AF_UNIX channel plus the pinned `O_PATH` root descriptor. It is the only
   namespace allowed by the public edge examples.
4. **Management network** — an outbound-established mesh VPN or other private
   network for administration. The full dashboard, SSH, API documentation, and
   setup flows belong here.
5. **Loopback service network** — the host-owned public-portal socket, Gateway,
   and other `casaos-*` service listeners. The portal process receives its
   listener through socket activation and cannot create IP sockets in its
   private network namespace. Gateway remains a distinct data path. Loopback is
   not an authentication mechanism for other local services.
6. **Storage and backup zone** — mounted data plus encrypted, access-separated
   backups. Restore operators are trusted but auditable.

## Threat actors and assumptions

Threat actors include unauthenticated Internet scanners, credential-stuffing
bots, malicious authenticated users or shared-link recipients, compromised
browsers, hostile uploaded files, compromised third-party integrations, and an
attacker with a foothold in one local component. Supply-chain compromise and
operator mistakes are also in scope.

This model assumes a supported, patched OS; least-privilege service accounts;
correct DNS/time; an uncompromised TLS edge and VPN identity; and a first admin
created over a trusted network. Physical attacks, a fully compromised kernel,
and denial of service beyond the provisioned edge capacity are not prevented by
this repository, but recovery plans must account for them.

## Principal attack paths and controls

| Threat | Current exposure / concern | Required controls and verification |
| --- | --- | --- |
| Direct service exposure | Gateway or a daemon bound to all interfaces bypasses edge policy. | The public edge upstream must be exactly the dedicated `127.0.0.1:39777` portal listener. Keep Gateway on a firewalled private/VPN address and non-public management port; public firewall allows only edge 80/443. Gateway's `/public-files` handler is an intentional 404 tombstone, never the portal data path. Scan from an external host and a LAN peer. |
| Legacy loopback auth bypass is enabled | The bypass is off by default and only the exact value `RECASAOS_TRUST_LOOPBACK_AUTH_BYPASS=1` enables it for a direct loopback socket peer. A loopback reverse proxy would make every proxied request eligible if an operator enables it. Forwarding headers are deliberately ignored. | Public deployments must leave the variable unset or `0`, never `1`; the public edge must target only the dedicated portal listener and never Gateway; direct upstream access must be impossible; still overwrite forwarding headers for other components; test unauthenticated requests and forged loopback headers for 401/403. |
| Broken authentication/session theft | Root APIs now require the `casaos` access-token issuer, so a same-key `refresh` token is rejected; external services still own issuance, enrollment, revocation, and password policy. Password guessing, initial setup left open, stolen JWTs, and legacy query-string tokens remain stack-level risks. | Create admin before exposure; rate-limit all credential/token routes; prefer edge MFA; use TLS only; short sessions/revocation where supported; never log query strings; test issuer confusion, logout, and revocation across every component. |
| Cross-origin abuse or outage | Root v1/v2 middleware denies cross-origin access by default and accepts only exact HTTP(S) origins from `RECASAOS_ALLOWED_ORIGINS`; wildcards and malformed origins are rejected. TLS termination makes the public HTTPS origin differ from the HTTP upstream unless it is configured explicitly. Adjacent components may have separate policies. | Set a comma-separated exact allowlist including the public HTTPS origin; never use `*`; keep UI/API same-origin; use Secure/HttpOnly/SameSite cookies where applicable; test hostile origins, preflight, and WebSockets across the locked stack. |
| File path or authorization flaw | Direct privileged file reads, writes, uploads, downloads, archives, rename, delete, thumbnail, listing, size/count, and asynchronous copy/move operations are confined to startup-pinned roots with descriptor-relative Linux `openat2`. Batch copies publish destination-local staging trees atomically, accept only explicit skip/replace/rename policies (plus the UI's exact `overwrite` alias), never follow links, reject link sources/top-level targets, special files, overlapping trees, configured-root targets, and mount crossings. The move filesystem allowlist does not restrict copy filesystem eligibility. Every regular-file or directory move requires both source and destination to be eligible local filesystems: ext2/3/4, XFS, Btrfs, tmpfs, or F2FS; this allowlist is an eligibility policy, not filesystem certification or authentication. Network, FUSE, and unknown filesystems fail closed before a move syscall or publication. Directory moves require a non-replacing same-filesystem atomic rename. Copy-first regular-file moves, including replace and cross-filesystem fallback, deliberately preserve the original source and report PARTIAL with `ErrManagedMoveSourceRetained`; automatic source deletion remains disabled until Issue #17 provides a durable ledger and recovery design. On normal copy-first completion the destination is synchronized and verified, so this is a known-durable partial. If a publication or transaction error occurs after the destination namespace changes, the same sentinel is joined to prove source retention and namespace publication, but aggregate `DurabilityUnknown` may be true and final destination synchronization or verification may be incomplete. A direct-rename source-name race is detected after the syscall and reported as partial, but Linux cannot condition the rename on an expected inode, so the raced object can move before detection; the implementation does not roll back or delete an ambiguous result. Destructive recursion has mount/depth/entry limits. The public portal uses a separate read-only pinned share with stricter hidden-name, hardlink, and mount-crossing rules. | Public edge exposes only `/public-files`; keep every privileged API on VPN; configure only operator-owned roots; trust and monitor the mount namespace; do not grant untrusted principals rename/write access to management parents; test traversal, symlinks, hardlinks, mount boundaries, races, cross-filesystem moves, conflict policies, and cross-user access. Independent deployment review remains required. |
| Browser download credential or memory leak | The supplied client does not intentionally write the bearer to persistent browser storage or a URL. A scoped Worker records a short-lived nonce and a separate 192-bit in-memory navigation proof bound to the exact top-level portal client/path/URL. The preparing page submits one same-origin top-level POST whose URL contains only the non-secret nonce fragment and whose body contains only that proof. Before consuming the reservation, the Worker requires the exact POST navigation, content type, path, URL, nonce, and proof; a copied URL, raw GET, invalid proof, timeout, restart, replay, or message failure returns an empty navigation response without challenging the page or making an authenticated upstream request. The Worker then requests the bearer once from the original page over a dedicated message port, erases the proof, strips the fragment, performs one same-origin header-authenticated fetch with credentials omitted, rejects redirects, and passes each response chunk through a backpressure-preserving monitor. The monitor retains an in-memory abort handle until EOF, cancellation, or error, so forgetting the token can stop an already handed but still-active stream without buffering the full file. The bearer necessarily exists transiently in page, Worker, request-header, edge, and server memory. Unsupported clients use a one-at-a-time, 32 MiB payload-bounded reader. If the Worker is bypassed, unauthenticated GET or POST browser navigations receive an empty `204` instead of replacing the portal; ordinary API clients retain `401`/`405`. The portal withholds `Last-Modified` and strong `ETag` values; a weak or unknown `If-Range` therefore falls back to a complete `200`, while an ordinary single initial `Range` remains `206`. Transparent retry/resume is intentionally not claimed because the nonce and proof are one-shot. | Keep Issue #20 open until real HTTPS Chromium/Firefox/WebKit tests verify no bearer retention in URL/referrer/history/storage/DevTools/proxy/application logs or crash artifacts, byte/filename round trips, bounded memory, two-tab isolation, restart/replay/logout/rotation failures, redirect denial, initial Range, retry/resume, and cancellation. The isolated Playwright smoke records one authenticated upstream initial-Range request and one `206` per bundled engine; it also requires consumed-proof replay to remain unauthenticated and page logout to cancel an already handed active stream. It does not prove stable retail browsers, Worker-process restart, token rotation, transparent retry/resume, or a target host. A trusted same-repository run may retain a one-day, pre-authorization navigation trace and structured diagnostics only after independent bearer and credential-metadata scans pass. Structured events omit all header and query/fragment values; the trace may contain ordinary pre-authorization browser request/response headers, but retention rejects `Authorization`, `Proxy-Authorization`, `Cookie`, and `Set-Cookie` headers plus non-empty parsed cookie metadata. Fork PRs, profiles, HAR, video, and HTML reports remain excluded. Server-side rotation cannot revoke a response that was already authorized and handed to the browser. Do not call a target host public-ready from repository tests. |
| Firefox CI navigation lifecycle desynchronization | On Firefox, Playwright can time out waiting for the external navigation lifecycle while the exact HTTPS portal document is already complete in the target page. Treating every such timeout as success would hide genuine navigation, TLS, or server failures. The stale lifecycle also blocks locator auto-wait after the document is available to direct evaluation. | Continue without retry only when the driver is exactly `about:blank`, both pages remain credential-free pre-auth documents at the exact portal URL, the captured main-frame response is a direct non-Service-Worker `GET` document with status `200`, the Go request delta is exactly one start and one completion with zero active/server/TLS errors, and a separate trusted TLS 1.3 probe returns `200`. Repeat the complete pre-auth proof immediately before return, then use direct in-document evaluation for the equivalent URL/ready/login/browser/token postcondition instead of the blocked locator auto-wait. The complete later cross-tab authorization and download-reservation assertions still run. Any missing or conflicting proof fails and follows the diagnostic path. |
| Public bearer or verifier exposure | The supported candidate never provisions or persists the raw bearer as a server credential; authorized requests still deliver it transiently in the `Authorization` header. An administrator generates an `rc1_` plus base64url-no-pad encoding of 32 random bytes on an independent workstation, keeps its durable copy only in a password manager, and installs only `recasaos-public-verifier-v1:sha256:<64 lowercase hex>` followed by one LF through the dedicated verifier setting. The standalone binary accepts only a strict CLI contract and rejects every non-empty legacy `RECASAOS_PUBLIC_FILE_*` environment setting. A disclosed verifier does not satisfy bearer authentication, but it remains protected configuration and can expose rotation state. systemd may represent its runtime copy as root-owned mode `0440`, where the apparent group bits are an ACL mask; the loader accepts that form only with the exact named-service-UID read ACL, empty group/other access, and no extra entries. Plain group-readable `0440` remains rejected. | Load the strict verifier through a systemd credential, set `LimitCORE=0`, reject malformed, linked, ambiguously named, or broadly accessible verifier files, and never log bearer or verifier material. Issue #26's bind-alias, legacy-setting, atomic publication, restart, rotation, and rollback gates are complete, but every target host must still exercise them. The raw bearer must never enter host configuration, shell history, durable storage, or logs; treat edge and server request memory as part of the live credential boundary. |
| Blocking public root filesystem | Before returning a usable portal, a disposable bootstrap worker records the public share's `statx` mount ID and `fstatfs` type and passes the coordinator only an `O_PATH` root descriptor, verifier digest, and fixed metadata. Only ext2/3/4, XFS, Btrfs, tmpfs, and F2FS are eligible; FUSE, network, overlay, ZFS, and unknown types fail closed. Every later list/open/read runs in a same-binary disposable worker which revalidates the descriptor, mount identity, filesystem policy, path, and response protocol. The coordinator admits at most eight active workers, applies fixed deadlines, requests SIGKILL through an atomically acquired pidfd, quarantines killed children until they are reaped, and refuses new work after four retained quarantines. Any non-ESRCH pidfd signaling failure closes all later admission and retains the active slot until reap; it never falls back to a reusable numeric PID. The coordinator is nondumpable before loading the verifier, reports systemd readiness only after bootstrap and HTTP accept, and requires its exact unified cgroup v2 unit at runtime. Three individually bound control files must have unique reviewed mount IDs, exact service-cgroup roots, read-only cgroup2 mounts, and the effective `memory.max=536870912`, `memory.swap.max=0`, and `pids.max=256` values. The remaining containment is unit-wide task, memory, swap, and control-group kill bounds plus per-process descriptor limits. The service and socket also refuse activation when the host lacks the cgroup v2 memory, swap, or pids controller files. An allowlisted filesystem can still be backed by a remote or failing block device, and SIGKILL cannot complete a syscall already stuck in uninterruptible kernel sleep. | Keep Issues #22 and #25 open. Keep the mount namespace and storage stack operator-controlled. The allowlist is an eligibility policy, not proof that the kernel, disk, or underlying block device cannot hang. The 12-second bootstrap deadline bounds coordinator waiting but cannot guarantee physical child exit; up to eleven children can be retained in one coordinator generation when eight active workers follow three earlier quarantines, while older cgroup remnants rely on the unit-wide limits. ZFS and other excluded local filesystems require dedicated compatibility evidence and a reviewed policy change, never an unrestricted fallback. Mount tests require an explicit opt-in and root, prove they are outside PID 1's mount namespace, reject remaining shared propagation, and run only in the dedicated ephemeral CI job under `unshare --mount --propagation private`. Do not close Issue #25 or claim production public readiness until exact-head Linux verifies the effective kernel limits and real FUSE/device-mapper/D-state, cancellation, restart, cleanup, and resource-headroom evidence proves the bounded worker design. |
| Destructive management operation | System stop, SSH-over-WebSocket, Samba, storage, batch, and integration routes have high impact. Legacy `curl | bash` automatic update execution is disabled until signed ReCasaOS manifests and rollback exist. | Keep management routes on VPN; require reauthentication for dangerous actions where supported; audit actions; never expose debug/API docs publicly. |
| SMB parser, credential, or downgrade attack | SMB discovery runs only in a same-binary child which, when the service starts as root, drops to `nobody`, removes supplementary groups, applies process/resource limits, proves that sandbox with a fixed `READY` handshake, and only then receives bounded credentials over stdin. Credentials are absent from argv/environment; stdout/stderr, time, concurrency, share count, and names are bounded. Discovery and server configuration require SMB signing, and kernel CIFS mounts use `sign` with port 445 only. Guest/anonymous shares and privileged `force user` mappings are disabled. | Run the service only under the reviewed unit and keep Samba patched. The helper must run as UID/GID 65534 with no supplementary groups; every other non-root identity fails closed. Root/the service UID and the kernel remain trusted; the handshake narrows but cannot eliminate every pre-exec host-local inspection race. Verify signed discovery, signed mount compatibility, child limit tests, and negative malformed-server cases on each supported Linux release. |
| Legacy Samba migration or config race | Only byte-exact upstream CasaOS main configuration plus an exact multiset of raw database-derived legacy stanzas is eligible for automatic migration. Eligible rows are transactionally renamed and made private; Unicode, injection-shaped, duplicate, noncanonical, or otherwise unsafe rows remain as database evidence but are omitted from the active candidate. Dedicated byte-preserving backups are mode `0600` and the old `.bak` is untouched. Config publication uses inode/digest/permission compare-and-swap; detected unknown files are quarantined and block future publication. Empty post-unmount directories are deliberately retained because pathname cleanup after releasing mount ownership is unsafe. | Review quarantined DB rows and `.recasaos-quarantine-*` files manually; never re-enable the old guest/root fragment. A non-cooperating root or same-service-UID process racing after the final CAS identity check is within the trusted-host boundary. Migration backups intentionally remain for audit and can cause repeated migration reconciliation until an administrator resolves retained unsafe rows. Test exact, reordered, mixed-safe/unsafe, restart/commit failure, crash-resume, backup, and concurrent-replacement cases. |
| SQLite pathname replacement or secret logging | Database setup walks every ancestor with no-follow descriptors. Ancestors must be root/service-owned; group/other-writable ancestors are rejected unless sticky rename protection applies and the child is root/service-owned. The final directory is service-owned `0700`; the database, WAL, SHM, and journal are service-owned single-link regular files forced to `0600`. The canonical pathname must still identify the pinned directory before and after initialization. SQL warning logs use parameterized queries. | Do not relocate the DB beneath an untrusted writable hierarchy. SQLite canonicalizes `/proc/self/fd` paths, so the implementation deliberately does not claim descriptor-bound auxiliary filenames. Root and the service UID remain trusted after initialization. Use encrypted storage/backups when confidentiality at rest is required; test non-sticky writable ancestors, rename/replacement identity checks, symlink/hardlink artifacts, WAL metadata, permissive umask, and log redaction. |
| WebSocket hijacking or exhaustion | Root file/SSH sockets validate Origin, cap messages/connections, use bounded queues and deadlines, and overwrite client sender identity. SSH passwords are accepted only from a verified POST-issued one-use ticket or the first socket frame, and the local SSH host key must match protected system key material. The legacy UI still emits ignored credentials and JWTs in its WebSocket URL, so browser/Gateway logging remains a release blocker until that UI is patched. External-component sockets remain separate risks. | Keep all WebSockets off the public file hostname; patch and pin the UI so credentials and long-lived JWTs never enter URLs; use short-lived one-use socket tickets; test host-key mismatch, expiry/replay/revocation, normal session exit, slow output, and saturation across the locked stack. |
| Upload/download denial of service | Root multipart handlers cap chunks at 256 MiB, files at 64 GiB/256 chunks, and active v1/v2 sessions at 16 per registry. Completed replay tombstones are bounded at 128, expiry cleanup is retryable, indexes are checked before allocation, and final publication binds the assembled file's full stat identity plus SHA-256. Assembly streams and upload paths resolve through pinned roots. Aggregate disk quota and hostile local-parent rename races remain concerns. | Keep privileged upload APIs on VPN; add per-user/disk quotas and reserved system space; keep upload parents unavailable to untrusted local writers; monitor private temporary uploads; test 413/429, interruption, concurrency, replay, archive budgets, and disk exhaustion. |
| SSRF and third-party credential theft | Root proxy/search fetches are bound to separate capabilities and exact service endpoint allowlists, including host, path, and query shape. They require canonical HTTPS on port 443, re-check DNS and redirects under the same capability, disable ambient proxies, share a bounded transport, and cap response headers and bodies. Cloud, OAuth, DDNS, ZeroTier, update checks, and external components still cross trust boundaries. | Keep the capability allowlists narrow and pair them with an egress policy; use scoped credentials and encrypted secret storage; regression-test lookalike hosts, unexpected paths/queries, userinfo, IPv4/IPv6 special ranges, DNS rebinding, cross-capability redirects, and credential logging. |
| Local component compromise | Shared runtime files, public keys, message bus, Gateway management, and privileged OS operations create lateral movement paths. | Separate Unix users and writable paths; authenticate local IPC; minimize capabilities/sudo; protect runtime files; audit service-unit hardening. |
| Supply-chain drift | The Message Bus OpenAPI input, generator, Go toolchain, and Actions are pinned, and dangerous inherited workflows plus remote-shell updates are disabled. A structured CI package-graph gate rejects the unmaintained `golang.org/x/crypto/openpgp` subtree across Linux tests in both CGO modes, race-enabled tests, privileged browser/systemd tags, supported release targets, the checker, and selected Go tools without blocking the separately required `golang.org/x/crypto/ssh` package. Tool graphs are checked before generators execute and the full selected graph is checked again afterward. UI/installer/runtime components are not yet locked as one release. | Follow `RECASAOS_COMPONENTS.md`; pin every release component/action to reviewed immutable revisions; generate before test; scan dependencies; verify checksums, SBOM, signatures, and provenance. The package gate prevents a known forbidden import family from becoming selected in the enumerated graphs; it is not a general vulnerability scanner, does not cover unselected platform/tag combinations, and does not prove that allowed dependencies are safe. |
| Backup compromise or failed recovery | Backups contain files, tokens, databases, and configuration; an untested copy may be inconsistent. | Encrypt with separate keys, restrict/monitor access, use snapshots or quiesce databases, keep an offline/off-account copy, and regularly restore into an isolated host. |

## Static-analysis triage boundary

An automated alert dismissal is an audit classification, not proof that a
surface is safe to expose. ReCasaOS does not dismiss path alerts merely because
the file manager intentionally accepts administrator-selected paths. Direct file
operations now map those paths to explicit roots and perform I/O relative to
pinned descriptors, including the asynchronous copy/move worker. Issue #7
remains open because Linux has no expected-inode conditional rename/unlink
primitive: a same-service-UID or root writer, including one acting through a
different mount namespace, can change a writable parent after the final check.
The direct-move path detects a mismatched destination after `renameat2` and
reports a partial mutation without rollback, but detection cannot prevent the
raced object from moving. Until Issue #17 supplies a durable ledger and
recovery protocol, copy-first moves never delete the source. Normal completion
returns a known-durable partial after synchronizing and verifying the
destination. If a publication or transaction error follows namespace
publication, the source-retained sentinel is joined with that error;
`DurabilityUnknown` may then be true and final destination synchronization or
verification may be incomplete.
Copy publication remains available on non-allowlisted filesystems, but every
no-replace rename error, including `EEXIST`, is treated as an ambiguous
publication outcome unless `fstatfs` proves an allowlisted local filesystem.
The private transaction is retained as evidence, mutation/durability are
reported unknown, and no destination path or processed bytes are claimed. Only
on a proven allowlisted local filesystem is `EEXIST` handled as the explicit
conflict policy.
An authenticated management endpoint can now inventory exact-format retained
transactions under one explicitly selected parent. The observation is bounded,
single-level, descriptor-relative, and no-follow. It never intentionally changes
content, namespace, permissions, or durability state. Directory enumeration
requires `O_NOATIME` and fails closed instead of retrying without it; a remote
filesystem server can still maintain access metadata outside the process's
control. It reports only `empty_unclassified`, `entry_present_unclassified`, or
`unverified`, with the recovery role always `unknown`; it never reports an entry
as safe to delete.
Non-standard names created by an external rename cannot be discovered without a
durable ledger, and incomplete or truncated observations remain manual-review
evidence. Startup reconciliation, role classification, filesystem capability
certification, and cleanup remain open in Issue #17.
Tests and the CodeQL gate verify these controls but do not eliminate that
trusted-host residual, which reinforces the private/VPN-only management
boundary.

The public portal does not use those pathname helpers. It resolves only beneath
its pinned share descriptor with Linux `openat2`. Outbound fetches are likewise
capability-bound: each caller receives only the exact service endpoints it needs,
canonical HTTPS on port 443, a direct transport that resolves and dials only
checked public addresses, same-capability redirect validation, and response
header/body limits. Static-analysis results for either boundary must be reviewed
against the complete data path; false-positive or accepted-risk classifications
must retain a written justification and a tracking issue where hardening remains.

## Public-readiness blockers

The portal and positive-allowlist edge examples close the root repository's
basic public route-separation requirement, but these release gates remain:

- Issue #27 remains open until the default-branch exact-SHA promotion workflow
  is exercised against a real pull request and its uniquely named status is
  required from the verified GitHub Actions provider on `main`. Fork and
  Dependabot code must receive no write token or repository secret. A skipped
  privileged job is not evidence, and a successful status on an earlier head
  cannot satisfy a later commit;
- Issue #22 remains open until the staged filesystem gate has exact-HEAD Linux
  evidence and the residual blocking-storage boundary has an explicit reviewed
  disposition;
- Issue #25's bounded worker protocol is implemented as a release candidate,
  but the issue remains open until exact-head Linux and real
  FUSE/device-mapper/D-state tests prove timeout, quarantine, cgroup cleanup,
  restart, cancellation, and resource-headroom behavior. A dedicated CI job
  boots the clean exact commit under PID 1 in a checksum-pinned, pristine
  Debian 11/systemd 247 unified-cgroup-v2 QEMU TCG VM and runs the live
  isolation suite; a skipped or failed job is not compatibility evidence.
  Because systemd 247 does not yet auto-bind its notification socket into
  `RootDirectory=`, the service carries the equivalent non-recursive read-only
  bind explicitly. Its minimal root pre-creates a root-owned target directory
  that is not writable by the service identity, plus a placeholder, so
  `UMask=0077` cannot produce a root-only traversal path on that manager. The
  live suite verifies that the jailed
  socket is the host manager socket and is mounted read-only;
  `NotifyAccess=main` limits accepted readiness messages to the service's main
  process. The software-emulated guest receives a policy-locked 30-second
  aggregate window to admit eight concurrently launched holders, while the
  native hosted test retains 15 seconds. All clients, stopped workers, and the
  exact first-read/capacity event chain remain mandatory; journal propagation
  has a separate 10-second evidence-only bound. A single root-only `/proc`
  snapshot checks all eight stopped identities, limits, bearer absence, memory
  ownership, descriptor flags, and listener non-inheritance so observer
  process startup cannot consume the service deadline under TCG. Per-worker
  IPC, service, resource, and cleanup bounds are unchanged.
  This closes the earlier parser-only evidence gap for heads on which the job
  succeeds, but does not close Issue #25 or substitute for real hostile-storage
  and exact target-host recovery evidence. Ubuntu 24.04/systemd 255 evidence
  alone does not satisfy the compatibility-floor gate.
  Its normal activation, sandbox and API smoke checks use the production build,
  while the deterministic worker-capacity and coordinator-cleanup sections
  temporarily use a non-release CI build tag that stops only the exact
  synthetic fixture worker after one successful read. Those sections prove
  admission, pidfd cancellation and control-group cleanup mechanics, not
  release-byte equivalence or D-state;
- no independent deployment review or penetration test of a locked Linux host;
- the shared portal token is a capability, not per-user authorization or MFA;
- Issue #20's browser-stream candidate still lacks the required real-HTTPS
  Chromium/Firefox/WebKit memory, filename, initial-Range, retry/resume,
  cancellation, restart, replay, logout, and rotation evidence. The
  repository's isolated Ubuntu 24.04 browser smoke uses an ephemeral
  runner-trusted CA and the Playwright-bundled Chromium, Firefox, and WebKit
  engines without disabling TLS verification; its initial-Range case records
  one authenticated upstream request and one `206` per bundled engine. That
  remains loopback handler/frontend evidence, not stable retail
  Chrome/Firefox/Safari, a real edge, production systemd, target-host, or
  transparent retry/resume evidence. Its cancellation smoke
  requires every engine to report local cancellation to Playwright and exactly
  one authorized upstream request to reach a terminal state within the
  test-harness deadline. Chromium and WebKit must classify that request as
  canceled; Firefox may classify it as canceled or completed. That outcome is
  consistent with Mozilla
  [Bug 1825388](https://bugzilla.mozilla.org/show_bug.cgi?id=1825388), which
  remains open for a related Service Worker cancellation path, but does not
  establish the same root cause; that branch proves bounded fixture cleanup,
  not cancellation propagation;
- stock Caddy needs a separate, reviewed request-rate limiting edge/WAF; the
  supplied Caddy example provides routing, header, TLS, and body-size controls
  but does not itself rate-limit requests;
- the new exact-origin policy and default-off loopback bypass still require
  full-stack configuration and regression evidence; public deployments must
  never set `RECASAOS_TRUST_LOOPBACK_AUTH_BYPASS=1`;
- the admin UI must be forked and pinned so its SSH socket stops emitting raw
  username/password/JWT query values; the backend ignores those credentials
  and requires a one-use ticket, but cannot erase values the legacy browser has
  already placed in its URL;
- other query-string token flows need removal or tightly controlled
  compatibility handling;
- the UI and Message Bus runtime artifact are not yet locked as reproducible
  full-stack release inputs (the generated Message Bus API specification itself
  is pinned to an immutable upstream commit);
- no evidence in this repository of an independent penetration test, full-stack
  restore drill, or supported security response SLA.

Until these gates are closed, expose the full ReCasaOS management surface only
through a private network. Only the separately scoped `/public-files` capability
may be considered for an Internet edge, and only after the deployment guide's
acceptance matrix passes on the target host.

## Review triggers

Update this model whenever authentication, CORS, file path handling, WebSocket
routes, local IPC, privileges, an external integration, the installer, update
mechanism, edge topology, or component lock changes. Every security incident or
restore failure must also produce a threat-model update and a regression test.
