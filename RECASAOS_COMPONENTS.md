# ReCasaOS component boundaries and version locks

ReCasaOS is a cross-component system. This repository is the root backend and
integration point; a green build here does **not** prove that every runtime
component or the browser UI is compatible, patched, or releasable.

## What this repository owns

| Area | Source of truth in this repository | Boundary |
| --- | --- | --- |
| Root service | `main.go`, `route/`, `service/`, `pkg/`, `internal/` | Registers CasaOS API routes with the Gateway and performs file, storage, system, and integration operations. |
| Public file portal | `pkg/publicfiles/`, `deploy/`, `docs/deployment/public-access.md` | Opt-in read-only capability with a server-side root and independent token. It does not make administrative APIs public-ready. |
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
| Gateway | Discovered through `CasaOS-Common/external` at runtime | Owns the private management listener, administrative routing, dashboard entry point, and upstream client-IP forwarding. It must not be the public-file edge upstream. The root service separately owns the literal-loopback public-portal listener; Gateway's registered `/public-files` handler is only a 404 tombstone. |
| User/authentication service | Reached through Gateway routes and runtime public-key material | Owns account enrollment, token issuance, revocation, and session policy. Root endpoints validate its JWTs; end-to-end authentication must be tested across both components. |
| Message Bus | Runtime address is discovered via `CasaOS-Common`; its client is generated from the OpenAPI document at upstream commit `ba87168fcfa4ac5ff7a114f66a139eb5fe427646` | Event delivery is optional in parts of the root service, but schema drift can still break notifications. Updating the pinned specification requires review and regenerated-client tests. |
| App management and other `casaos-*` daemons | Routed or queried through Gateway/runtime integration | Installation, privilege, health, and compatibility are separate release gates. |
| Installer, OS packaging, and service units | External to this repository | Decide users, capabilities, filesystem permissions, bind addresses, upgrades, and rollback. They are part of the security boundary even when the root binary is unchanged. |

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
   are reviewed changes and must pass tests, `go vet`, and `govulncheck`.
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
