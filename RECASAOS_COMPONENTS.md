# ReCasaOS component boundaries and version locks

ReCasaOS is a cross-component system. This repository is the root backend and
integration point; a green build here does **not** prove that every runtime
component or the browser UI is compatible, patched, or releasable.

## What this repository owns

| Area | Source of truth in this repository | Boundary |
| --- | --- | --- |
| Root service | `main.go`, `route/`, `service/`, `pkg/`, `internal/` | Registers CasaOS API routes with the Gateway and performs file, storage, system, and integration operations. |
| Public file portal | `cmd/recasaos-public-files/`, `pkg/publicfiles/`, `build/sysroot/usr/lib/systemd/system/recasaos-public-files.*`, `deploy/`, `docs/deployment/public-access.md` | Opt-in read-only capability in a separate non-root, socket-activated service with a pinned server-side root and independent bearer credential. The host provisions only its verifier. It does not make administrative APIs public-ready. |
| Root OpenAPI contract | `api/casaos/openapi.yaml` | Generates the `codegen` server/types used by the root service. Contract changes require compatibility review with all clients. |
| Configuration sample | `conf/conf.conf.sample` | Documents root-service settings only; it is not a complete deployment manifest for the full CasaOS stack. |
| Root release and CI | `.goreleaser*.yaml`, `.github/workflows/` | Builds and checks this repository. External services remain independently versioned. |

Generated files under `codegen/` are tracked build products. They must be
regenerated and diff-checked before tests and release builds; they must never
be hand-edited.

## Components outside this repository

| Component | How the root currently reaches it | Ownership / risk boundary |
| --- | --- | --- |
| Administrative Web UI | `.gitmodules` declares `UI` from `IceWhaleTech/CasaOS-UI` on `main` | Dashboard/login behavior lives outside the root Go service. The dedicated public-files page is embedded locally and does not depend on this UI. This checkout has no tracked `UI` gitlink, so `--recurse-submodules` cannot provide a reproducible admin UI revision. |
| CasaOS Common | Go module `github.com/IceWhaleTech/CasaOS-Common` | Supplies shared runtime discovery, Gateway management, and JWT helpers. Its API and security behavior are locked through `go.mod` plus `go.sum`. |
| SMB2 client fork | Go module `github.com/EdmundFu-233/go-smb2@v1.1.1-recasaos.1`, release commit `11ee3a1e5240a64ccb0223983243f29d6b710413` | ReCasaOS-maintained BSD-2-Clause fork of `hirochachacha/go-smb2` v1.1.0. It carries reviewed directory-response and 32-bit payload bounds, pins Go 1.25 / toolchain 1.26.6 and `x/crypto` v0.55.0, and deliberately excludes CloudSoda and SDDL. The root module graph must select this exact tag directly. |
| Gateway | Discovered through `CasaOS-Common/external` at runtime | Owns the private management listener, administrative routing, dashboard entry point, and upstream client-IP forwarding. It must not be the public-file edge upstream. The independent `recasaos-public-files.socket` owns the literal-loopback portal listener; Gateway's registered `/public-files` handler is only a 404 tombstone. |
| User/authentication service | Reached through Gateway routes and runtime public-key material | Owns account enrollment, token issuance, revocation, and session policy. Root endpoints validate its JWTs; end-to-end authentication must be tested across both components. |
| Message Bus | Runtime address is discovered via `CasaOS-Common`; its client is generated from the OpenAPI document at upstream commit `ba87168fcfa4ac5ff7a114f66a139eb5fe427646` | Event delivery is optional in parts of the root service, but schema drift can still break notifications. Updating the pinned specification requires review and regenerated-client tests. |
| App management and other `casaos-*` daemons | Routed or queried through Gateway/runtime integration | Installation, privilege, health, and compatibility are separate release gates. |
| Installer and full OS packaging | External to this repository | Decide component versions, upgrades, and rollback. This repository contains candidate CasaOS and isolated public-file units, but the full installer must preserve their reviewed users, capabilities, filesystem permissions, bind addresses, and default-disabled public exposure. |

## Locking policy

1. A ReCasaOS release must identify one immutable commit or artifact digest for
   every external component. Branch names such as `main`, `latest`, or a moving
   container tag are not release locks.
2. ReCasaOS forks are preferred for patched components. If an upstream artifact
   is used unchanged, record its upstream repository, immutable revision,
   checksum, license, and the date it was reviewed.
3. The UI must be represented by a tracked gitlink (or a checksum-verified build
   artifact). The `branch = main` hint in `.gitmodules` is not a lock.
4. Go dependencies remain locked by `go.mod` and `go.sum`. Dependency upgrades
   are reviewed changes and must pass tests, `go vet`, and `govulncheck`. CI
   also decodes Go's selected-package graph for Linux tests in both CGO modes,
   the race-enabled test selection, privileged browser and systemd build-tag
   selections, every supported
   Linux release architecture in both CGO modes, the boundary checker, and the
   `go.mod` tool graph in both CGO modes. Tool graphs are checked before any
   generator executes and the complete graph is checked again afterward. CI
   rejects `golang.org/x/crypto/openpgp` and every package below that boundary.
   This is intentionally a package boundary, not a ban on the complete
   `golang.org/x/crypto` module: the separately required
   `golang.org/x/crypto/ssh` package remains allowed. A separate module gate
   requires exactly `github.com/EdmundFu-233/go-smb2@v1.1.1-recasaos.1`
   without a `replace`, and rejects the upstream hiro module, either CloudSoda
   path spelling, SDDL, and any other unreviewed `go-smb2` fork as direct
   modules or replacements.
5. OpenAPI generators and input specifications are both supply-chain inputs.
   The local root specification, generator version, and remote Message Bus
   specification commit are explicit. Verify regenerated output whenever one
   of those pins changes.
6. Release automation should consume a committed component manifest containing
   component name, repository, commit/digest, artifact SHA-256, API/schema
   version, license, and compatibility status. Until that manifest and the
   missing UI lock exist, builds from this root are development builds, not a
   reproducible full-stack release.

## Compatibility and update rules

- Change a contract producer and all affected consumers in one compatibility
  plan. Land tolerant consumers before producers when a rolling update is
  required.
- Keep a tested compatibility matrix for root service, Gateway, auth service,
  Message Bus, App Management, UI, and installer. Record both upgrade and
  rollback results.
- Preserve upstream commit provenance when importing fixes. Security patches
  receive threat-model review in addition to ordinary functional review.
- Never let CI silently fetch a newer runtime component for a release. CI may
  fetch build tools, but release inputs must resolve to reviewed immutable
  identifiers and verified checksums.
- A root-only CI pass is necessary but not sufficient. A release candidate also
  needs clean-install, upgrade, authentication, file-operation, WebSocket,
  backup/restore, and rollback tests against the locked full stack.
