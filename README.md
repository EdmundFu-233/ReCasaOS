# ReCasaOS

[![ReCasaOS CI](https://github.com/EdmundFu-233/ReCasaOS/actions/workflows/recasaos-ci-security.yml/badge.svg)](https://github.com/EdmundFu-233/ReCasaOS/actions/workflows/recasaos-ci-security.yml)
[![CodeQL](https://github.com/EdmundFu-233/ReCasaOS/actions/workflows/codeql.yml/badge.svg)](https://github.com/EdmundFu-233/ReCasaOS/actions/workflows/codeql.yml)
[![License](https://img.shields.io/github/license/EdmundFu-233/ReCasaOS)](LICENSE)
[![Issues](https://img.shields.io/github/issues/EdmundFu-233/ReCasaOS)](https://github.com/EdmundFu-233/ReCasaOS/issues)

ReCasaOS is a community continuation fork of
[IceWhaleTech/CasaOS](https://github.com/IceWhaleTech/CasaOS). Its purpose is to
keep the CasaOS ecosystem maintainable by fixing security defects, reliability
bugs, dependency drift, unsafe release automation, and deployment gaps while
preserving compatibility where that does not weaken the security boundary.

## Current status

**Development foundation — not yet an installable full-stack release.** This
repository owns the CasaOS root backend, while Gateway, UserService, UI, App
Management, Message Bus, installer, and packaging remain separate components.
A green root build is not proof that an arbitrary mix of those components is
safe or compatible.

Do not use `get.casaos.io` install or update scripts to install ReCasaOS. Those
scripts are controlled by the upstream CasaOS project and do not install the
fixes in this fork. ReCasaOS will publish an installer only after every runtime
component is pinned, clean-install and upgrade/rollback tests pass, and release
artifacts have checksums and provenance.

The first hardening milestone includes:

- default-off loopback authentication bypass and exact-origin CORS/WebSocket
  checks;
- access/refresh JWT issuer separation and protected debug routes;
- bounded, traversal-resistant multipart uploads and safer streaming downloads;
- an opt-in, read-only `/public-files` portal confined with Linux `openat2`, a
  server-owned root, and a separate header-only bearer token;
- bounded root file/SSH WebSockets, verified local SSH host keys, one-use SSH
  login tickets, and removal of an SSH infinite retry path;
- capability-bound outbound fetches with exact endpoint allowlists and
  DNS/redirect/IP revalidation;
- fail-closed cloud OAuth recovery until one-time state and PKCE are available;
- maintained archive/OpenAPI implementations and upgraded vulnerable
  dependencies;
- secret-safe request/OAuth logging, restrictive file permissions, CodeQL,
  Dependabot, and reachable-vulnerability CI;
- reviewed Caddy/Nginx edge examples, a threat model, and explicit component
  release gates.

See [the threat model](docs/THREAT_MODEL.md) for the remaining blockers and
[the component lock policy](RECASAOS_COMPONENTS.md) for the full-stack boundary.

## Public access

The full administrative dashboard is **not ready for unrestricted Internet
exposure**. Keep it on a private management network or mesh VPN. ReCasaOS now
has a separate read-only public file portal on a dedicated literal-loopback
listener (default `127.0.0.1:39777`). The examples in [the public-access
guide](docs/deployment/public-access.md) proxy only that listener and positive
route allowlist. Gateway's `/public-files` registration is an intentional 404
tombstone for stale-route cleanup and is never the portal upstream. A
particular host is not public-ready until the guide's deployment, restore,
scanning, and independent-review gates pass.

Never expose Samba, SSH, daemon ports, debug/API documentation, setup routes,
privileged v1/v2/v3 APIs, the dedicated portal listener, or root/Gateway
listeners directly. Keep the management Gateway on a firewalled private/VPN
address and non-public port; public 80/443 belong only to the route-allowlisted
TLS edge. Never enable `RECASAOS_TRUST_LOOPBACK_AUTH_BYPASS=1` behind a reverse
proxy. The Nginx example includes rate and connection limits; a public stock
Caddy deployment needs a separately reviewed rate-limiting edge/WAF in front.

## Development

ReCasaOS currently requires Linux for the complete build and test suite. The Go
toolchain and generator versions are locked in `go.mod`; the remote Message Bus
OpenAPI input is locked to an immutable commit.

```sh
go generate ./...
go test ./...
go vet ./...
govulncheck ./...
```

On a non-Linux development host, compile the complete Linux package graph with:

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -exec=true ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...
```

`-exec=true` verifies cross-platform compilation but does not execute the Linux
test binaries. GitHub Actions executes the full suite on Ubuntu with the patched
Go version recorded in the workflow.

## Contributing and security

Use [ReCasaOS issues](https://github.com/EdmundFu-233/ReCasaOS/issues) for bugs,
compatibility work, and scoped roadmap items. Keep one security or reliability
problem per commit where practical and include a regression test.

Report vulnerabilities privately through the repository Security tab as
described in [SECURITY.md](SECURITY.md). Do not put exploits, credentials,
private host details, or personal data in a public issue.

## Provenance and license

ReCasaOS preserves the upstream module path and binary/service names for
compatibility while the component migration is staged. This does not imply
endorsement by or affiliation with IceWhaleTech.

CasaOS was created by IceWhaleTech and its contributors. Their history remains
in this Git repository, and upstream fixes should retain commit provenance.
ReCasaOS is distributed under the repository's [Apache-2.0 license](LICENSE).
