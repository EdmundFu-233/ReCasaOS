# SMB server identity policy (RC scope)

## Trust anchor

ReCasaOS pins each SMB server on first operator-verified contact
(trust-on-first-use) and rejects every later silent change:

- `pkg/smbcredentials/server_identity.go` binds the normalized hostname,
  port, and full resolved address set. `Verify` runs at every reconnect.
- A hostname or port change fails with `ErrServerIdentityChanged`.
- An address-set change (DNS rebinding, silent failover, unexpected server
  answering for a pinned name) fails with `ErrServerAddressChanged`.
- Address changes are operator actions only, via `RotateAddresses` after
  out-of-band verification. There is no silent adaptation.

This pinning composes with, and does not replace, the existing controls:
mandatory SMB signing, disabled guest shares, mount ownership validation,
and private/VPN-only management (see `docs/THREAT_MODEL.md`).

## What this is not

- Not Kerberos/SPN: no ticket, keytab, or service-principal validation is
  performed. Kerberos/SPN binding in supported environments is deferred
  work tracked by issue #14.
- Not a certificate check: the pin carries no key continuity beyond the
  address set. A network adversary that holds both DNS and routing can
  present a consistent lie at first pin time; first contact must therefore
  happen over a trusted network with operator verification (below).
- DNS remains a trusted input at pin time. DNSSEC or static host entries
  are recommended for pinned servers.

## DNS and reconnect behavior

- Resolve the pinned hostname through the site resolver at every
  reconnect and pass the full address set to `Verify`.
- Any difference from the pinned set (added, removed, or replaced
  address, including IPv4/IPv6 family changes) is a hard failure.
- Retries may re-resolve, but must re-verify: resolution is never cached
  past one reconnect decision.
- Short names and FQDNs are distinct identities. Pin the exact name the
  clients use.

## Operator verification checklist (first pin and every rotation)

1. Confirm the hostname and port against inventory (not against DNS alone).
2. Confirm every resolved address belongs to the intended server
   (compare with console/iDRAC, static assignment, or DHCP reservation).
3. Record who verified, when, and over which network path.
4. Store the marshalled pin beside the keyring backup; back both up
   together (`BackupKeyring` / `RemoveBackup` semantics apply: backups
   never overwrite, rotation is explicit).

## Backup, restore, and recovery

- `BackupKeyring` publishes one canonical keyring image to the fixed
  backup name with create-only semantics; a second backup fails with
  `ErrBackupExists` instead of overwriting.
- `RestoreKeyring` parses the fixed backup name and validates mode 0400,
  ownership, link count, and size before parsing.
- Key loss without a backup is unrecoverable by design: sealed envelopes
  cannot be opened and must be re-sealed from source credentials after
  re-provisioning. There is no escrow and no recovery key.
