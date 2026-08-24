# ReCasaOS SMB credential formats

This package freezes two strict binary version-1 formats. Integers are unsigned
big-endian. Parsers reject truncation, trailing bytes, unknown versions,
unknown algorithms, non-zero reserved bytes, duplicate keys, non-derived key
IDs, and non-canonical ordering.

## Keyring v1

| Bytes | Field |
| ---: | --- |
| 8 | `RCSMBKEY` magic |
| 1 | version (`1`) |
| 1 | key count (`1..8`) |
| 32 | active key ID |
| repeated | entries sorted bytewise by key ID |
| 32 | entry key ID: SHA-256 of the raw key |
| 32 | entry XChaCha20-Poly1305 key-encryption key |

The complete keyring is secret. It is designed to be provided as the fixed
`recasaos-smb-keyring` systemd credential. A key ID is a non-secret lookup
identifier, not a password-derived key or an authentication result.

## Envelope v1

| Bytes | Field |
| ---: | --- |
| 8 | `RCSMBENV` magic |
| 1 | version (`1`) |
| 1 | algorithm (`1`, XChaCha20-Poly1305) |
| 2 | zero reserved bytes |
| 32 | wrapping key ID |
| 24 | DEK-wrap nonce |
| 48 | wrapped random 32-byte per-row DEK |
| 24 | password nonce |
| 2 | password ciphertext length |
| variable | password ciphertext and 16-byte tag |

Separate AEAD associated-data domains bind both layers to the format version,
canonical credential UUID, byte-exact username, host, port, and directories.
The wrapped-DEK domain also binds the wrapping key ID. Copying an envelope to a
different row or changing bound metadata therefore fails authentication.

### Associated data v1

Both domains use this canonical byte layout. There is no terminator or padding.

| Bytes | Field |
| ---: | --- |
| 8 | `RCSMBAAD` magic |
| 1 | envelope version (`1`) |
| 1 | purpose (`1` for wrapped DEK, `2` for password) |
| 16 | RFC 4122 UUID bytes |
| 32 or 0 | wrapping key ID, present only for purpose `1` |
| 2 + variable | username byte length (u16 big-endian), then bytes |
| 2 + variable | host byte length (u16 big-endian), then bytes |
| 2 + variable | port byte length (u16 big-endian), then bytes |
| 2 + variable | directories byte length (u16 big-endian), then bytes |

The textual credential ID must be the canonical lowercase RFC 4122 version-4
UUID rendering and must not be the nil UUID. Username and host are non-empty
valid UTF-8 with at most 255 bytes each. Port is exactly the UTF-8 string
`445`. Directories is non-empty valid UTF-8 with at most 16,384 bytes. Values
are bound byte-for-byte; this format does not case-fold, resolve, sort, or
otherwise normalize them. The password may be empty and is limited to 1,024
bytes.

Rotation first authenticates both layers, then changes only the wrapping key,
wrap nonce, and wrapped DEK. The password nonce and ciphertext stay unchanged.
Old keys may be removed only after a durable database scan authenticates every
envelope and proves that no row still references them.

Authenticating the complete envelope requires `Rewrap` to decrypt the password
briefly into a cleared in-process buffer. It does not re-encrypt or otherwise
change the password layer.

This foundation deliberately has no old-key retirement API. `Rotate` only adds
a new active key to an in-memory candidate and retains every prior key, up to
the strict eight-key format limit. A later database integration must implement
an authoritative complete scan, durable keyring publication, and fail-closed
retirement protocol before rotation is operationally complete.

## Runtime loading boundary

On Linux, the runtime loader accepts only the fixed `recasaos-smb-keyring`
credential below the runtime directory supplied by systemd in
`CREDENTIALS_DIRECTORY`. For the current root-run service, it requires an
effective-UID-owned directory with mode `0500` or `0700` and a regular,
single-link, effective-UID-owned credential with exact mode `0400`. The
directory and file are opened with no-follow semantics and the input is size
bounded before strict parsing.

This is designed for a systemd-v247-compatible root-service boundary. The
directory loader alone does not prove the runtime directory's ancestor or PID 1
provenance.

## Source provisioning boundary

On Linux, `ProvisionSystemKeyringSource` can generate and create only the fixed
`/etc/recasaos/recasaos-smb-keyring` source. It requires an already-existing
root-owned path boundary, never replaces or parses an existing destination, and
publishes a fully synchronized canonical keyring with kernel-enforced
no-replace semantics. Its result distinguishes a created-but-not-proven-durable
destination and an unresolved named staging object; either state is a hard
operator-recovery HOLD and must not be retried by generating another key.
Before the named fallback can rename, it synchronizes both the completed
candidate and the directory containing its fixed marker. On a filesystem that
honors these synchronization guarantees, a later machine crash therefore
recovers either the marker or the published target rather than silently
forgetting a generated, reachable key.
An occupied destination is likewise an unvalidated hard HOLD, not idempotent
success: the provisioner deliberately does not open, parse, repair, chmod, or
remove it.
If a publication syscall or subsequent namespace inspection has an ambiguous
outcome, the result conservatively reports the key as created with unknown
durability; a named-candidate ambiguity also reports cleanup required. These
states can overstate what reached disk, but they prevent an unsafe retry from
generating a second unrelated key.

The root-owned mode-`0700` namespace is also the serialization boundary for the
named fallback and operator recovery. Protocol-conforming concurrent callers
stop when the fixed `O_EXCL` marker exists. Recovery must be serialized with all
provisioning and other recovery activity: Linux has no single operation that
can conditionally rename or unlink a pathname only if it still names a
previously inspected inode. A concurrent out-of-protocol root process could
replace the marker between the identity check and the name-based operation;
root can already directly alter this source namespace.

The provisioner is deliberately not called by the service, installer, package
scripts, or units. It strictly parses a bounded readback only to validate the
published bytes, then destroys that parser state. It does not install
`LoadCredential=`, update a running systemd credential, expose a key ID,
return or activate the generated keyring as a runtime credential, access the
database, or migrate credentials. Those remain separate install, restart,
migration, and runtime validation gates. A future cutover must provision
durably, install and validate the unit boundary, restart into the new systemd
credential, and only then begin an atomic database migration.

## Boundary

These formats are intended to protect credentials in the current SQLite
database once the service integration is complete. This package does not read,
migrate, write, or scrub that database. It cannot erase historical backups,
snapshots, copy-on-write extents, SSD history, process memory, or kernel CIFS
mount buffers. It also does not authenticate SMB server identity or DNS. Those
are separate release gates.
