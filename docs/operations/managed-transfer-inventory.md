# Managed transfer transaction inventory

ReCasaOS may deliberately retain a private `.recasaos-transfer-*` directory
when it cannot prove publication or cleanup. The retained directory is recovery
evidence. It is not disposable temporary data.

The private management API provides a bounded, read-only observation endpoint:

```http
POST /v1/file/recovery/inventory
Authorization: Bearer <management access token>
Content-Type: application/json

{"parent":"/DATA/example-destination"}
```

The route is behind the existing v1 access-token middleware and inherits
`Cache-Control: private, no-store`. POST is intentional: the selected host path
does not enter the request target or query log. Keep this endpoint on the
private/VPN-only management surface; it is never part of `/public-files`.

The request accepts exactly one canonical absolute parent below
`RECASAOS_MANAGEMENT_FILE_ROOTS`. It examines only that directory's immediate
children and only names matching `.recasaos-transfer-` followed by 32 lowercase
hexadecimal characters. It does not recursively scan a root or mount.

Each item has one of these observed shapes:

- `empty_unclassified`: a descriptor-bound, service-owned mode-0700 directory
  was empty at observation time;
- `entry_present_unclassified`: the directory contained exactly one no-follow,
  same-mount regular file or directory named `entry`;
- `unverified`: metadata, contents, mount identity, or descriptor/name identity
  could not be proven.

`recovery_role` is always `unknown`. Without a durable crash-safe ledger, an
`entry` cannot be reliably classified as unpublished staging or an exchanged
old target. The returned mount ID, device, inode, mode, link count, size, and
type are evidence for review only; they are never authorization to delete.
Mount ID, device, and inode use fixed-width lowercase hexadecimal strings;
link count and size use decimal strings so JavaScript clients cannot round
64-bit values. Reported metadata and mode are observations, not filesystem
capability certification.

The response `data` uses separate item-level and snapshot-level diagnostics:

```json
{
  "parent": "/DATA/example-destination",
  "items": [
    {
      "name": ".recasaos-transfer-0123456789abcdef0123456789abcdef",
      "observed_state": "unverified",
      "recovery_role": "unknown",
      "finding": "contents_unexpected"
    }
  ],
  "complete": false,
  "truncated": true,
  "scanned": 4096,
  "candidate_count": 1,
  "findings": ["entry_limit_exceeded", "concurrent_mutation"]
}
```

An item's optional singular `finding` explains why that candidate is
`unverified`. The top-level optional `findings` array explains why the entire
snapshot is incomplete or truncated; it can contain multiple deduplicated
codes. These fields are independent. Stable item codes are
`candidate_open_failed`, `candidate_metadata_unsafe`,
`candidate_identity_changed`, `contents_unexpected`, `entry_open_failed`,
`entry_metadata_unsafe`, `entry_mount_changed`, `entry_identity_changed`, and
`directory_read_failed`. Stable snapshot codes are
`parent_identity_changed`, `directory_read_failed`, `entry_limit_exceeded`,
`candidate_limit_exceeded`, and `concurrent_mutation`.

`complete=false` means the snapshot must not be treated as exhaustive.
`truncated=true` means a fixed directory-entry or response-candidate bound was
reached. A read or parent-identity race also makes the result incomplete.

## Non-destructive operator workflow

1. Preserve the transaction directory and its parent. Do not rename, chmod,
   move, or remove either while collecting evidence.
2. Query only the known destination parent and record the complete response,
   service logs, operation status, and time of observation.
3. Treat every `unverified`, incomplete, or truncated result as requiring
   investigation. Do not retry a failed move as if no namespace mutation
   occurred.
4. Before any later manual recovery decision, take a verified backup or
   read-only snapshot and prevent non-cooperating writers from changing the
   parent. Compare the recorded identities with the destination and original
   source on a qualified Linux host.
5. Escalate unresolved evidence through Issue #17 or the private security
   reporting channel. ReCasaOS intentionally provides no cleanup endpoint.

Transactions renamed to a non-standard name by an external parent writer are
preserved but cannot be automatically discovered by this format-only inventory.
Startup reconciliation, reliable role classification, filesystem capability
certification, and audited cleanup remain tracked in Issue #17. This endpoint
does not make those acceptance criteria complete.
