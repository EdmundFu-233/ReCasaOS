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

The portal is deliberately limited:

- read-only directory listing and regular-file download;
- a server-configured root that cannot be `/`;
- a separate bearer token loaded from a root/service-owned `0600` file;
- header-only authentication (tokens in query strings are rejected);
- Linux `openat2` descriptor-relative access with `RESOLVE_BENEATH`,
  `NO_SYMLINKS`, `NO_MAGICLINKS`, and `NO_XDEV`;
- no hidden files, symlinks, hard-linked files, devices, sockets, pipes, or
  mount-boundary traversal;
- bounded directory listings, strict browser CSP, no-store responses, and no
  external browser assets.

### Browser download boundary (candidate)

The portal never persists its bearer token. The token exists only in the
current page's JavaScript memory and is forgotten on logout, page exit, or
reload; it is not written to cookies, URLs, history, `sessionStorage`,
`localStorage`, IndexedDB, or the Cache API.

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

There is intentionally no weaker fallback. Enabling the portal on a kernel or
seccomp profile without the required `openat2` policy makes startup fail. A
real procfs mounted at `/proc` is also required: token and download files are
first pinned with `O_PATH`, then reopened only through the internally generated
`/proc/self/fd/<fd>` path and revalidated. The required token read probes this
mechanism during portal initialization, so an unavailable procfd mechanism
also fails startup.

## 1. Prepare the share and token

Use a dedicated directory containing only files approved for public download.
Do not point it at a home directory, `/DATA`, an application-data tree, backup
root, secrets directory, or a writable upload staging area.

Use a reviewed local filesystem for this root. FUSE, NFS, CIFS/SMB and other
potentially blocking network or userspace filesystems are not public-ready:
socket deadlines cannot interrupt a kernel filesystem read that never returns.
Such a syscall can retain its in-process download slot until the syscall
returns; the progress budget only bounds response writes.
Fail-closed filesystem isolation is tracked separately in
[ReCasaOS issue #22](https://github.com/EdmundFu-233/ReCasaOS/issues/22);
until it is implemented and validated, keep those filesystem types outside the
portal root.

Example (replace the service account if ReCasaOS does not run as root):

```sh
sudo install -d -o root -g root -m 0750 /srv/recasaos-public
sudo install -d -o root -g root -m 0700 /etc/recasaos
umask 077
openssl rand -base64 48 | sudo tee /etc/recasaos/public-file.token >/dev/null
sudo chown root:root /etc/recasaos/public-file.token
sudo chmod 0600 /etc/recasaos/public-file.token
```

The token file must be a single-link regular file, owned by the effective
ReCasaOS service user, non-executable, and inaccessible to group/other users.
Its content must encode at least 32 random bytes in base64 or hexadecimal. The
token file must be outside the shared root.

Treat the token as a password. Transfer it out of band, never place it in a
URL, issue, shell history, reverse-proxy configuration, unit file, or log, and
rotate it after any suspected exposure.

## 2. Enable the portal

Set these variables in the root service's protected environment/drop-in:

```text
RECASAOS_PUBLIC_FILE_ENABLED=1
RECASAOS_PUBLIC_FILE_ROOT=/srv/recasaos-public
RECASAOS_PUBLIC_FILE_TOKEN_FILE=/etc/recasaos/public-file.token
RECASAOS_PUBLIC_FILE_LISTEN=127.0.0.1:39777
RECASAOS_TRUST_LOOPBACK_AUTH_BYPASS=0
```

The enable flag, root, and token file are required. The listener defaults to
`127.0.0.1:39777`, but setting it explicitly makes the deployment boundary
auditable. It accepts only a literal loopback IP and a canonical port from 1 to
65535; hostnames, wildcard/public addresses, and port zero make startup fail.
The feature remains disabled unless `RECASAOS_PUBLIC_FILE_ENABLED` is exactly
`1`; an enabled but unsafe or incomplete configuration fails closed during
startup. Never enable the legacy loopback auth bypass behind a reverse proxy.

Restart ReCasaOS, then verify locally that `127.0.0.1:39777/public-files/`
serves the portal. Gateway also registers `/public-files`, but that handler is a
deliberate 404 tombstone used to clear or prevent a stale historical route. It
does not serve files, and the public edge must never proxy Gateway for this
portal. Verify the tombstone returns 404 and that the dashboard remains
reachable only through its normal private access path. Do not print the token
during routine diagnostics.

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

Run these from an unrelated Internet connection. Substitute the real hostname
and load the token into a local shell variable without echoing it:

```sh
curl -fsS https://files.example.net/public-files/ >/dev/null
curl -sS -o /dev/null -w '%{http_code}\n' https://files.example.net/v1/sys/version/current
curl -sS -o /dev/null -w '%{http_code}\n' https://files.example.net/public-files/api/list
curl -fsS -H "Authorization: Bearer ${RECASAOS_TEST_TOKEN}" \
  'https://files.example.net/public-files/api/list?path='
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer ${RECASAOS_TEST_TOKEN}" \
  'https://files.example.net/public-files/api/list?token=must-not-be-accepted'
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
| Authentication | Missing, malformed, duplicate, wrong, query-string, and rotated tokens fail without revealing why. |
| Path confinement | Absolute/parent/encoded traversal, hidden names, symlinks, hardlinks, mount points, devices, pipes, and sockets cannot be listed or downloaded. |
| Browser boundary | CSP has no inline/eval allowance; the bearer exists only in current-page memory and never appears in a URL, Referer, history, cookie, Cache API, Web Storage, IndexedDB, or log. In stable Chromium, Firefox, and WebKit over real HTTPS, verify a large download starts without full-body buffering and preserves bytes/filename; replay, another tab, Worker restart, logout, rotation, redirect, and malformed messages fail closed. Record memory measurements and initial Range, retry/resume, and cancellation results. |
| Response handling | GET, HEAD, and one byte range work, including offsets above 4 GiB; multi-range work is rejected; 401/404/416/503 and successful private-file responses retain `no-store` and `nosniff`. A progressing transfer can cross the base write timeout, while idle and below-budget clients are terminated. |
| Client cancellation | After a large response starts, abort the client and verify that the chosen edge promptly closes its loopback upstream request and releases portal download capacity. Test both HTTP/1.1 and HTTP/2 at the public edge when both are enabled. |
| Resource bounds | Oversized directory and request-body tests fail; slow clients do not exhaust all edge connections. Nginx rate/connection limits or the separately reviewed Caddy-fronting limiter are exercised. |
| Logs | No bearer token, query, private host path, file content, cookie, or personal data appears in edge/application logs. |
| Backups | Share and configuration can be restored to an isolated host with recorded checksums and acceptable RPO/RTO. |

Any failed row blocks public DNS/exposure. Passing repository static tests does
not satisfy this target-host matrix. Retest after every routing, auth, kernel,
proxy, installer, or component change.

## Operational limits

The bearer token is a shared capability, not per-person authorization or MFA.
Use a separate portal/root/token per trust group, rotate tokens regularly, and
remove access immediately when a recipient leaves. Rotation blocks new
requests but cannot retract bytes already handed to a browser download manager.
The native browser-stream candidate keeps the bearer header-only; unsupported
browsers are limited to the bounded 32 MiB fallback. Until Issue #20's browser
matrix passes, use a separately reviewed streaming client that can set an
Authorization header for large files.

For upload, sharing links, expiry, audit identities, per-user policy, previews,
or remote administration, use a separately isolated and independently tested
file product. Do not re-enable the privileged v1/v2/v3 file APIs on the public
hostname to obtain those features.

This repository supplies the application boundary and deployment baseline; a
specific host becomes public-ready only after the acceptance matrix, restore
drill, vulnerability gates, and independent deployment review pass for its
locked component set.
