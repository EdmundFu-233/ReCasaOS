# ReCasaOS Development

ReCasaOS is a community continuation fork of
[IceWhaleTech/CasaOS](https://github.com/IceWhaleTech/CasaOS). This document
covers setting up a development environment for the **root backend** service.

## Supported platforms

- **Runtime**: Linux (kernel ≥ 5.8 for `openat2` and mount-ID checks)
- **Development / contributor build**: Linux or macOS (Darwin)

On non-Linux hosts the binary compiles to a clear refusal stub and
Linux-specific tests are skipped. See the [README](README.md) for the full
runtime requirements.

## Pre-requisites

| Tool | Minimum | Purpose |
| --- | --- | --- |
| Go | 1.25+ (toolchain 1.26.5+) | Compile, vet, test |
| Git | 2.x | Source control |
| `gh` | 2.x | (Optional) GitHub CLI for PR management |

A Node.js / yarn setup is **not** required for the root backend. The admin UI is
a separate component ([RECASAOS_COMPONENTS.md](RECASAOS_COMPONENTS.md)).

## Getting started

```sh
git clone https://github.com/EdmundFu-233/ReCasaOS.git
cd ReCasaOS
```

## Building

### Linux (native)

```sh
go build -o casa .
go test ./...
go vet ./...
```

### macOS (cross-compile to Linux)

```sh
# Verify compilation — does NOT execute Linux test binaries
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go test -exec=true ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go vet ./...

# Native Darwin vet (checks non-Linux stubs compile)
go vet ./...
```

### Build the public-file service

```sh
make build-public-files
```

## Code generation

OpenAPI types/server and Message Bus client are generated from spec files.
Regenerate them after changing `api/casaos/openapi.yaml`:

```sh
go generate ./...
```

Generated files under `codegen/` are tracked build products. They must be
regenerated and diff-checked before tests and release builds; they must never
be hand-edited.

## Testing

```sh
# Full test suite (Linux only — requires /proc, cgroup v2, etc.)
go test ./...

# Race detector
go test -race ./...

# Skip Linux-specific tests on macOS
go test ./... -skip '^TestPorts$'

# Run a specific package
go test ./pkg/sambasecurity/...
go test ./service/...
```

### Test categories

| Category | Location | Platform |
| --- | --- | --- |
| Unit tests | `*_test.go` in each package | Cross-platform (most) |
| Linux security tests | `*_linux_test.go` | Linux only |
| File mutation tests | `service/file_upload_mutation_linux_test.go` | Linux only (needs mounts) |
| Browser smoke tests | `browser-tests/` | CI only (Playwright) |

## Security development guidelines

1. **Never commit secrets** — `.env`, tokens, SSH keys stay in `.gitignore`
2. **Bound all inputs** — request bodies, headers, query params must have size limits
3. **Use `filesecurity` for file operations** — management file roots are pinned at startup
4. **Build-tag Linux-specific code** — use `//go:build linux && !android`
5. **Add regression tests** for every security fix
6. **One security/reliability issue per commit** where practical

## Project structure

```
├── main.go                  # Linux-only root service entry point
├── main_unsupported.go      # Darwin/non-Linux refusal stub
├── generate.go              # go:generate directives
├── api/                     # OpenAPI specifications
├── codegen/                 # Generated server/client code (tracked)
├── cmd/                     # Secondary binaries (public-files, migration-tool)
├── common/                  # Shared constants and event types
├── conf/                    # Configuration samples
├── internal/                # Internal packages (driver, config, etc.)
├── model/                   # Data models
├── pkg/                     # Reusable packages
│   ├── authsecurity/        # JWT/access token validation
│   ├── filesecurity/        # Management file root pinning, openat2
│   ├── httpsecurity/        # CORS, security headers, loopback bypass
│   ├── netsecurity/         # Network security utilities
│   ├── publicfiles/         # Isolated public-file portal
│   ├── samba/               # Samba probe and configuration
│   ├── sambasecurity/       # Encrypted credential keyring (XChaCha20-Poly1305)
│   ├── sshsecurity/         # SSH host key verification
│   └── ...
├── route/                   # HTTP route handlers (v1, v2, v3)
├── service/                 # Business logic layer
├── build/                   # Systemd units and sysroot
├── deploy/                  # Deployment configurations
├── docs/                    # Threat model, deployment guides, operations
├── browser-tests/           # Playwright browser smoke tests
└── .github/workflows/       # CI: security checks, CodeQL, trusted-privileged
```

## Contributing

See [SECURITY.md](SECURITY.md) for vulnerability reporting. Use
[ReCasaOS issues](https://github.com/EdmundFu-233/ReCasaOS/issues) for bugs
and roadmap items.
