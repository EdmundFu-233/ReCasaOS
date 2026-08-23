// Package smbcredentials defines the cryptographic storage boundary for
// ReCasaOS SMB passwords.
//
// It deliberately does not integrate with the connection database by itself.
// A database migration must validate, seal, and round-trip legacy plaintext;
// authenticate every existing envelope; update all rows in one transaction;
// scrub SQLite artifacts; and finish before the service announces readiness.
// Keeping this primitive separate makes the format and its failure behavior
// reviewable before that irreversible cutover.
package smbcredentials
