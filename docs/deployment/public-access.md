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

There is intentionally no weaker fallback. Enabling the portal on a kernel or
seccomp profile without the required `openat2` policy makes startup fail.

## 1. Prepare the share and token

Use a dedicated directory containing only files approved for public download.
Do not point it at a home directory, `/DATA`, an application-data tree, backup
root, secrets directory, or a writable upload staging area.

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
| Browser boundary | CSP has no inline/eval allowance; token remains in `sessionStorage`; hostile framing/origin cannot read responses. |
| Response handling | GET, HEAD, and ranges work; private files return `no-store`, `nosniff`, and attachment headers. |
| Resource bounds | Oversized directory and request-body tests fail; slow clients do not exhaust all edge connections. Nginx rate/connection limits or the separately reviewed Caddy-fronting limiter are exercised. |
| Logs | No bearer token, query, private host path, file content, cookie, or personal data appears in edge/application logs. |
| Backups | Share and configuration can be restored to an isolated host with recorded checksums and acceptable RPO/RTO. |

Any failed row blocks public DNS/exposure. Retest after every routing, auth,
kernel, proxy, installer, or component change.

## Operational limits

The bearer token is a shared capability, not per-person authorization or MFA.
Use a separate portal/root/token per trust group, rotate tokens regularly, and
remove access immediately when a recipient leaves. The UI downloads through
browser memory to keep credentials out of URLs; very large files may be better
served by a separately reviewed streaming client that can set an Authorization
header.

For upload, sharing links, expiry, audit identities, per-user policy, previews,
or remote administration, use a separately isolated and independently tested
file product. Do not re-enable the privileged v1/v2/v3 file APIs on the public
hostname to obtain those features.

This repository supplies the application boundary and deployment baseline; a
specific host becomes public-ready only after the acceptance matrix, restore
drill, vulnerability gates, and independent deployment review pass for its
locked component set.
