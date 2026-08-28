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

The production `casaos` startup now distinguishes exactly one
legacy-compatible loader result: the process environment has no
`CREDENTIALS_DIRECTORY` entry and `LoadSystemdKeyring` returns
`ErrSystemdCredentialNotProvided` directly. Once that environment entry
exists, an empty directory value, a missing fixed credential, unsafe metadata,
malformed bytes, or an unsupported platform is a hard startup failure before
configuration, database, service, route, or READY side effects. A valid
credential is parsed, then its `Keyring` is immediately destroyed before
startup continues because this expand-only release has no sealed DAO or other
authorized key consumer. Internal probe and version-only invocations bypass
this admission path.

The packaged base `casaos.service` deliberately contains no active credential
directive so an unprovisioned legacy installation can still reach the existing
strict legacy-only database gate. The exact `LoadCredential=` drop-in is staged
under `/usr/share/recasaos/systemd/casaos.service.d/` and is not installed in a
systemd search path. Activating it is a separate operator gate after durable
source provisioning and audit; once active, a missing source is intentionally
a systemd start failure.

The packaging checker fixes the reviewed base unit, rejects alternate active
`casaos.service` files, and requires both CasaOS-specific and type-wide
`service.d` drop-ins to be empty. It also inspects system-manager configuration
for credential or environment injection. Packaged system and
system-environment generators are disallowed because their output cannot be
proven by static inspection. This claim is limited to the packaged sysroot
systemd configuration and generator paths inspected by the checker; setup or
maintainer scripts require separate review. Runtime manager environment
changes, kernel command-line injection, and operator-created units remain
external configured inputs and therefore fail closed rather than being treated
as legacy absence.

Successful startup admission proves only that one bounded runtime payload was
safely opened and canonically parsed during that call. It does not prove PID 1
or source-file provenance, source durability, provisioning history, continued
path identity, database/keyring correspondence, sealed-row readiness, or
credential activation. The legacy-only database classifier remains
authoritative, and the admitted key is not retained or used to encrypt,
decrypt, migrate, rewrap, or scrub any row.

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

`CheckSystemKeyringSourceStructure` is a separate, read-only structural
snapshot of that same fixed source path. It requires the same root-owned ancestor and mode-`0700`
namespace boundary, refuses to inspect while the fixed staging marker exists,
first pins the target without opening its contents, then opens it read-only
while requesting no-follow, nonblocking, and no-atime semantics. It binds both
descriptors and the fixed name to the same regular single-link root-owned
mode-`0400` inode, strictly parses only a bounded buffer, then immediately
destroys the parsed state and clears the input bytes. It returns no keyring,
key ID, bytes, or other key material and has no production call site.

A successful source audit proves only that the current object was safely bound
and structurally canonical during that call. It does not establish who created
it, whether its original publication reached durable storage, whether the name
will still refer to that inode after return, whether it matches any runtime or
database state, whether it should be activated, or whether an occupied
destination can be treated as idempotent provisioning success. Provisioning
therefore continues to reject every occupied destination without opening or
accepting it.

The error-only audit API is also fail-closed. `ErrSourceKeyringMissing` is used
only after the safe namespace, marker, and target absence are repeatedly
confirmed; it does not authorize provisioning or retry.
`ErrSourceCleanupRequired` means the staging marker exists or could not be
inspected. `ErrUnsafeSourceKeyring` covers an unsafe or inconsistent boundary,
target, or read, and malformed bytes also preserve `ErrInvalidKeyring` for
`errors.Is`. Other I/O failures are indeterminate hard failures. Non-Linux
builds return `ErrSourceAuditUnsupported`.

## Transactional pending cutover boundary

The package-private SQLite staging core has no production call site. It does
not run from `main`, `GetDb`, a service, route, unit, installer, or migration
CLI. Its only successful durable result is `sealed + pending`; it never writes
the `complete` marker and therefore never authorizes service construction,
mount restore, API traffic, READY notification, or credential activation.

The core accepts only one file-backed SQLite `main` database with no attached
schema, in `DELETE` or `WAL` journal mode. On one pinned `database/sql`
connection it sets and reads back `trusted_schema=OFF`,
`writable_schema=OFF`, `ignore_check_constraints=OFF`, `foreign_keys=ON`,
`recursive_triggers=OFF`, `synchronous=FULL`, and `secure_delete=ON`, then uses
`BEGIN IMMEDIATE`. Before materializing credential fields it rejects
case-insensitive temporary schema shadows; main or temporary triggers directly
attached to the connection, marker, or key-control tables; any foreign key
whose child or parent is one of those tables; hidden/generated or unknown
connection columns; conflicting security schema; mixed/partial rows; unknown
markers; and resource bounds. Unrelated triggers and unrelated foreign-key
graphs remain allowed because the cutover cannot make them fire or cascade.

The preflight permits at most 4,096 rows and 4 MiB of total plaintext password
data. It also bounds every password to 1,024 bytes, username and host to 255
bytes, directories to 16 KiB, envelope-v1 blobs to their exact 158..1,182-byte
range, and all other materialized metadata both per field and in aggregate.
After the bounded read but before any credential-row, marker-row, or control-row
write, the core applies the same username/password/host/port, directory, and
mount-ownership semantics consumed by the runtime. A SQL `NULL` port is invalid
storage; only an empty TEXT legacy port is normalized to `445`.

The same transaction creates this exact singleton control table and binds even
an empty database to the 32-byte active key ID:

```sql
CREATE TABLE o_smb_credential_key_control (
    singleton INTEGER NOT NULL PRIMARY KEY CHECK (
        typeof(singleton) = 'integer' AND singleton = 1
    ),
    active_key_id BLOB NOT NULL CHECK (
        typeof(active_key_id) = 'blob' AND length(active_key_id) = 32
    ),
    revision INTEGER NOT NULL CHECK (
        typeof(revision) = 'integer' AND revision >= 1
    )
) WITHOUT ROWID
```

For every strict legacy row, the transaction generates a canonical UUIDv4,
normalizes only an empty legacy port to `445`, seals the bounded password,
immediately opens and compares the generated envelope, and performs an
exact-row compare-and-set update. The plaintext column becomes SQL `NULL`, the
envelope is stored as a BLOB, and `row_revision` becomes `1`. A complete
authoritative scan must then authenticate every envelope and prove that its
authenticated wrapping-key ID equals the singleton control value before the
pending marker can commit. Before `COMMIT`, an operation error uses a separate,
bounded cleanup context to roll the marker, control table, and every row back
together. A rollback failure discards the physical connection and reports an
unknown transaction outcome. A `COMMIT` error is also outcome-unknown: the
connection is discarded and a caller must close, durably reopen, and classify
the database before deciding what happened. It must never generate new UUIDs
or envelopes as a blind retry. A pending retry makes no durable state change
and requires the same active key plus another authoritative full scan, although
it still takes the immediate writer lock for one stable classification.

This transaction does not prove that the systemd runtime payload matches the
durable `/etc/recasaos` source. Before any future production caller can begin,
a separate descriptor-safe, error-only comparison gate must prove equality of
the runtime and source keyrings without returning key bytes or IDs. The caller
must then close and durably reopen the pending database, authenticate it,
checkpoint and scrub the current SQLite database/WAL/journal artifacts,
reauthenticate, and have a sealed-only runtime DAO before a separate
coordinator may write `complete`.

`secure_delete=ON` and a committed `password=NULL` are not physical-erasure
claims. Until the later scrub succeeds, old plaintext can remain in the main
file, freelist, rollback journal, WAL, backups, copy-on-write snapshots, storage
history, process memory, or kernel buffers. A `pending` database is recovery
state and must never reach normal startup.

## Boundary

These formats are intended to protect credentials in the current SQLite
database once the service integration is complete. This package does not read,
migrate, write, or scrub that database. It cannot erase historical backups,
snapshots, copy-on-write extents, SSD history, process memory, or kernel CIFS
mount buffers. It also does not authenticate SMB server identity or DNS. Those
are separate release gates.
