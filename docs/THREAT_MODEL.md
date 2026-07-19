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
   confinement. It uses a dedicated literal-loopback listener, defaulting to
   `127.0.0.1:39777`, and is the only namespace allowed by the public edge
   examples.
4. **Management network** — an outbound-established mesh VPN or other private
   network for administration. The full dashboard, SSH, API documentation, and
   setup flows belong here.
5. **Loopback service network** — the dedicated public-portal listener,
   Gateway, and other `casaos-*` service listeners. The portal listener and
   Gateway are distinct data paths. Loopback is not an authentication
   mechanism; local compromise crosses it.
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
| File path or authorization flaw | Privileged v1/v2/v3 file APIs still accept client-selected host paths and are management-only. The public portal instead pins a non-root directory fd and rejects traversal, hidden names, links, special files, and mount crossings with `openat2`; it is read-only. | Public edge exposes only `/public-files`; keep privileged APIs on VPN; use a dedicated share and token per trust group; test traversal, symlinks, hardlinks, mount boundaries, races, and cross-user access. Independent deployment review remains required. |
| Destructive management operation | System stop, SSH-over-WebSocket, Samba, storage, batch, and integration routes have high impact. Legacy `curl | bash` automatic update execution is disabled until signed ReCasaOS manifests and rollback exist. | Keep management routes on VPN; require reauthentication for dangerous actions where supported; audit actions; never expose debug/API docs publicly. |
| WebSocket hijacking or exhaustion | Root file/SSH sockets validate Origin, cap messages/connections, use bounded queues and deadlines, and overwrite client sender identity. SSH passwords are accepted only from a verified POST-issued one-use ticket or the first socket frame, and the local SSH host key must match protected system key material. The legacy UI still emits ignored credentials and JWTs in its WebSocket URL, so browser/Gateway logging remains a release blocker until that UI is patched. External-component sockets remain separate risks. | Keep all WebSockets off the public file hostname; patch and pin the UI so credentials and long-lived JWTs never enter URLs; use short-lived one-use socket tickets; test host-key mismatch, expiry/replay/revocation, normal session exit, slow output, and saturation across the locked stack. |
| Upload/download denial of service | Root multipart handlers cap chunks at 256 MiB, files at 64 GiB/256 chunks, and active v2 sessions at 16 with expiry cleanup; indexes are checked before allocation and assembly streams. Client-selected bases, aggregate disk quota, symlink TOCTOU in management uploads, and archive traversal races remain concerns. | Keep privileged upload APIs on VPN; add per-user/disk quotas and reserved system space; monitor isolated temporary uploads; test 413/429, interruption, concurrency, archive budgets, and disk exhaustion. |
| SSRF and third-party credential theft | Root generic proxy/search fetches now require public HTTPS on port 443, re-check DNS and redirects, disable ambient proxies, and cap response bodies. Cloud, OAuth, DDNS, ZeroTier, update checks, and external components still cross trust boundaries. | Keep egress policy and integration-specific destination allowlists; use scoped credentials and encrypted secret storage; regression-test IPv4/IPv6 private ranges, DNS rebinding, redirects, and credential logging. |
| Local component compromise | Shared runtime files, public keys, message bus, Gateway management, and privileged OS operations create lateral movement paths. | Separate Unix users and writable paths; authenticate local IPC; minimize capabilities/sudo; protect runtime files; audit service-unit hardening. |
| Supply-chain drift | The Message Bus OpenAPI input, generator, Go toolchain, and Actions are pinned, and dangerous inherited workflows plus remote-shell updates are disabled. UI/installer/runtime components are not yet locked as one release. | Follow `RECASAOS_COMPONENTS.md`; pin every release component/action to reviewed immutable revisions; generate before test; scan dependencies; verify checksums, SBOM, signatures, and provenance. |
| Backup compromise or failed recovery | Backups contain files, tokens, databases, and configuration; an untested copy may be inconsistent. | Encrypt with separate keys, restrict/monitor access, use snapshots or quiesce databases, keep an offline/off-account copy, and regularly restore into an isolated host. |

## Public-readiness blockers

The portal and positive-allowlist edge examples close the root repository's
basic public route-separation requirement, but these release gates remain:

- no independent deployment review or penetration test of a locked Linux host;
- the shared portal token is a capability, not per-user authorization or MFA;
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
