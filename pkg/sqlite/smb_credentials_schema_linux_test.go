//go:build linux

package sqlite

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	getDBSchemaHelperMode = "RECASAOS_TEST_GETDB_SCHEMA_MODE"
	getDBSchemaHelperPath = "RECASAOS_TEST_GETDB_SCHEMA_PATH"
)

func TestGetDbSMBCredentialSchemaIntegration(t *testing.T) {
	if mode := os.Getenv(getDBSchemaHelperMode); mode != "" {
		runGetDbSMBCredentialSchemaHelper(t, mode, os.Getenv(getDBSchemaHelperPath))
		return
	}

	t.Run("publishes database only after successful expansion", func(t *testing.T) {
		databasePath := filepath.Join(secureSQLiteTestRoot(t), "database")
		if err := os.Mkdir(databasePath, 0o700); err != nil {
			t.Fatal(err)
		}
		database, handle := openSMBCredentialSchemaDatabaseAt(t, filepath.Join(databasePath, "casaOS.db"))
		createHistoricalConnectionsSchema(t, database)
		if err := database.Exec(
			"INSERT INTO o_connections(id, username, password) VALUES (?, ?, ?)",
			71,
			"integration-user",
			"integration-password",
		).Error; err != nil {
			t.Fatal(err)
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		output := runGetDbSchemaSubprocess(t, "success", databasePath)
		if strings.Contains(output, "integration-password") {
			t.Fatalf("GetDb success output exposed a password: %s", output)
		}

		database, handle = openSMBCredentialSchemaDatabaseAt(t, filepath.Join(databasePath, "casaOS.db"))
		defer closeSMBCredentialSchemaDatabase(t, handle)
		if err := verifySMBCredentialSchema(database); err != nil {
			t.Fatal(err)
		}
		if err := verifyLegacyOnlySMBCredentialState(database); err != nil {
			t.Fatal(err)
		}
		var password string
		if err := database.Raw("SELECT password FROM o_connections WHERE id = ?", 71).Scan(&password).Error; err != nil {
			t.Fatal(err)
		}
		if password != "integration-password" {
			t.Fatalf("GetDb expansion changed legacy password: equal=%t", password == "integration-password")
		}
	})

	t.Run("failure leaves global unpublished and rolls back schema objects", func(t *testing.T) {
		databasePath := filepath.Join(secureSQLiteTestRoot(t), "database")
		if err := os.Mkdir(databasePath, 0o700); err != nil {
			t.Fatal(err)
		}
		database, handle := openSMBCredentialSchemaDatabaseAt(t, filepath.Join(databasePath, "casaOS.db"))
		createHistoricalConnectionsSchema(t, database)
		for _, statement := range []string{
			addConnectionBootIDSQL,
			addConnectionMountIDsSQL,
			addCredentialIDSQL,
			addCredentialFormatSQL,
			addPasswordEnvelopeSQL,
			addConnectionRowRevisionSQL,
		} {
			if err := database.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
		}
		envelope := []byte("GETDB-ENVELOPE-SENTINEL")
		if err := database.Exec(`INSERT INTO o_connections(
			id, username, password, credential_id, credential_format, password_envelope, row_revision
		) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			72,
			"integration-user",
			"GETDB-PASSWORD-SENTINEL",
			"11111111-1111-4111-8111-111111111111",
			"recasaos-smb-envelope-v1",
			envelope,
			1,
		).Error; err != nil {
			t.Fatal(err)
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		output := runGetDbSchemaSubprocess(t, "failure", databasePath)
		for _, sentinel := range []string{"GETDB-PASSWORD-SENTINEL", "GETDB-ENVELOPE-SENTINEL"} {
			if strings.Contains(output, sentinel) {
				t.Fatalf("GetDb failure output exposed %s: %s", sentinel, output)
			}
		}

		database, handle = openSMBCredentialSchemaDatabaseAt(t, filepath.Join(databasePath, "casaOS.db"))
		defer closeSMBCredentialSchemaDatabase(t, handle)
		assertSchemaObjectCount(t, database, "table", "o_security_migrations", 0)
		assertSchemaObjectCount(t, database, "index", smbCredentialIDIndexName, 0)
		var persisted []byte
		if err := database.Raw("SELECT password_envelope FROM o_connections WHERE id = ?", 72).Row().Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(persisted, envelope) {
			t.Fatalf("GetDb failure changed envelope: got=%x", persisted)
		}
	})
}

func runGetDbSMBCredentialSchemaHelper(t *testing.T, mode, databasePath string) {
	t.Helper()
	if databasePath == "" {
		t.Fatal("missing helper database path")
	}
	switch mode {
	case "success":
		database := GetDb(databasePath)
		if database == nil || gdb != database || databaseDirectory == nil {
			t.Fatal("GetDb returned before publishing its fully initialized database")
		}
		if err := verifySMBCredentialSchema(database); err != nil {
			t.Fatal(err)
		}
		if err := verifyLegacyOnlySMBCredentialState(database); err != nil {
			t.Fatal(err)
		}
	case "failure":
		var recovered any
		func() {
			defer func() { recovered = recover() }()
			_ = GetDb(databasePath)
		}()
		if recovered == nil {
			t.Fatal("GetDb unexpectedly accepted sealed state in expand-only mode")
		}
		if gdb != nil || databaseDirectory != nil {
			t.Fatal("GetDb published global state after failed expansion")
		}
		for _, sentinel := range []string{"GETDB-PASSWORD-SENTINEL", "GETDB-ENVELOPE-SENTINEL"} {
			if strings.Contains(fmt.Sprint(recovered), sentinel) {
				t.Fatalf("GetDb panic exposed %s", sentinel)
			}
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
}

func runGetDbSchemaSubprocess(t *testing.T, mode, databasePath string) string {
	t.Helper()
	command := exec.Command(os.Args[0], "-test.run=^TestGetDbSMBCredentialSchemaIntegration$")
	command.Env = append(os.Environ(), getDBSchemaHelperMode+"="+mode, getDBSchemaHelperPath+"="+databasePath)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("GetDb helper %s failed: %v\n%s", mode, err, output)
	}
	return string(output)
}
