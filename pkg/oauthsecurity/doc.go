// Package oauthsecurity provides the fail-closed primitives for cloud-driver
// OAuth: single-use state records, PKCE verifiers, strict runtime provider
// configuration, and a bounded authorization-code exchange client.
//
// The package deliberately has no production call site yet. It exists so the
// secure flow can be reviewed and tested before any provider is advertised
// again. The legacy cloud callback accepted an unauthenticated code without
// state or PKCE and wrote a root-owned rclone configuration, allowing
// cross-site authorization-code injection; nothing in this package may be
// wired into a route until the complete flow (state, PKCE, exchange, sealed
// token storage, rotation, and revocation) is independently reviewed.
//
// Boundary rules enforced here:
//   - state values are single-use, expire, are bound to the authenticated
//     principal and the exact redirect URI, and are stored only as SHA-256
//     digests so a memory disclosure cannot replay a live flow;
//   - PKCE S256 is mandatory; a provider that cannot use it is unsupported;
//   - provider client secrets come only from the process environment or a
//     root-owned 0600 credential file, never from source or URLs;
//   - the exchange client posts to exactly the configured token URL over
//     HTTPS, never follows redirects, never proxies, and bounds the response;
//   - refresh tokens rest only as versioned XChaCha20-Poly1305 envelopes
//     bound to provider, principal, and sealing key ID, with rotation that
//     leaves exactly one valid form and revocation checked before decrypt;
//   - provider failures surface only as curated redacted sentinels; raw
//     provider strings never reach callers or logs.
package oauthsecurity
