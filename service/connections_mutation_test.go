package service

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var connectionMutationTestNow = time.Unix(1_778_888_888, 0).UTC()

const connectionMutationTestSchema = `
CREATE TABLE o_connections (
	id INTEGER PRIMARY KEY,
	updated INTEGER,
	created INTEGER,
	username TEXT,
	password TEXT,
	credential_id TEXT,
	credential_format TEXT,
	password_envelope BLOB,
	row_revision INTEGER NOT NULL DEFAULT 0,
	host TEXT,
	port TEXT,
	status TEXT,
	directories TEXT,
	mount_point TEXT,
	boot_id TEXT,
	mount_ids TEXT
);
CREATE UNIQUE INDEX ux_o_connections_credential_id
	ON o_connections(credential_id)
	WHERE credential_id IS NOT NULL AND credential_id <> '';
CREATE TABLE o_security_migrations (
	name TEXT PRIMARY KEY NOT NULL,
	state TEXT NOT NULL CHECK (state IN ('pending', 'complete')),
	updated INTEGER NOT NULL
) WITHOUT ROWID;
`

type connectionMutationFingerprint struct {
	ID               string
	Updated          string
	Created          string
	Username         string
	Password         string
	CredentialID     string
	CredentialFormat string
	PasswordEnvelope string
	RowRevision      string
	Host             string
	Port             string
	Status           string
	Directories      string
	MountPoint       string
	BootID           string
	MountIDs         string
}

func TestLegacyConnectionMutationsHappyPath(t *testing.T) {
	t.Run("create uses an explicit legacy-only projection", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "create.db", false)
		connections := &connectionsStruct{db: database}
		connection := &model.ConnectionsDBModel{
			Username:         "alice",
			Password:         "correct horse battery staple",
			CredentialID:     "",
			CredentialFormat: "",
			PasswordEnvelope: []byte{},
			RowRevision:      0,
			Host:             "nas.local",
			Port:             "445",
			Status:           "ready",
			Directories:      "Media,Backups",
			MountPoint:       "/mnt/nas.local",
			BootID:           "boot-a",
			MountIDs:         `{"Media":11,"Backups":12}`,
		}

		if err := connections.CreateConnection(connection); err != nil {
			t.Fatalf("CreateConnection() error = %v", err)
		}
		if connection.ID == 0 {
			t.Fatal("CreateConnection() did not publish the generated row ID")
		}

		var stored model.ConnectionsDBModel
		if err := database.First(&stored, connection.ID).Error; err != nil {
			t.Fatalf("read created connection: %v", err)
		}
		if stored.Username != connection.Username ||
			stored.Password != connection.Password ||
			stored.Host != connection.Host ||
			stored.Port != connection.Port ||
			stored.Status != connection.Status ||
			stored.Directories != connection.Directories ||
			stored.MountPoint != connection.MountPoint ||
			stored.BootID != connection.BootID ||
			stored.MountIDs != connection.MountIDs {
			t.Fatalf("created legacy fields = %#v, want %#v", stored, *connection)
		}
		if stored.Created != connectionMutationTestNow.Unix() || stored.Updated != connectionMutationTestNow.Unix() {
			t.Fatalf("created timestamps = (%d, %d), want (%d, %d)", stored.Created, stored.Updated, connectionMutationTestNow.Unix(), connectionMutationTestNow.Unix())
		}
		assertConnectionCredentialStorageTypes(t, database, connection.ID, "null", "null", "null", "integer")
	})

	t.Run("mount-state update touches only its typed columns", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "update.db", false)
		seedLegacyConnection(t, database, 41)
		seedLegacyConnection(t, database, 99)
		neighborBefore := fingerprintConnectionMutationRow(t, database, 99)
		connections := &connectionsStruct{db: database}

		if err := connections.UpdateConnectionMountState(41, "", "", "", ""); err != nil {
			t.Fatalf("UpdateConnectionMountState() error = %v", err)
		}

		var stored model.ConnectionsDBModel
		if err := database.First(&stored, 41).Error; err != nil {
			t.Fatalf("read updated connection: %v", err)
		}
		if stored.Created != 101 || stored.Username != "user-41" || stored.Password != "password-41" ||
			stored.Host != "host-41" || stored.Status != "status-41" || stored.MountPoint != "/mnt/host-41" {
			t.Fatalf("typed update changed immutable legacy fields: %#v", stored)
		}
		if stored.Updated != connectionMutationTestNow.Unix() || stored.Port != "" || stored.Directories != "" || stored.BootID != "" || stored.MountIDs != "" {
			t.Fatalf("typed update fields = %#v", stored)
		}
		assertConnectionCredentialStorageTypes(t, database, 41, "text", "text", "blob", "integer")
		if neighborAfter := fingerprintConnectionMutationRow(t, database, 99); neighborAfter != neighborBefore {
			t.Fatalf("typed update changed neighboring row\nbefore=%#v\nafter=%#v", neighborBefore, neighborAfter)
		}
	})

	t.Run("no-op update still matches exactly one row", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "no-op.db", false)
		seedLegacyConnection(t, database, 42)
		if err := database.Exec("UPDATE o_connections SET updated = ? WHERE id = ?", connectionMutationTestNow.Unix(), 42).Error; err != nil {
			t.Fatalf("align timestamp: %v", err)
		}
		connections := &connectionsStruct{db: database}
		if err := connections.UpdateConnectionMountState(42, "1445", "Media", "boot-old", `{"Media":42}`); err != nil {
			t.Fatalf("no-op UpdateConnectionMountState() error = %v", err)
		}
	})

	t.Run("delete removes exactly one legacy row", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "delete.db", false)
		seedLegacyConnection(t, database, 43)
		seedLegacyConnection(t, database, 44)
		neighborBefore := fingerprintConnectionMutationRow(t, database, 44)
		connections := &connectionsStruct{db: database}
		if err := connections.DeleteConnection("43"); err != nil {
			t.Fatalf("DeleteConnection() error = %v", err)
		}
		if rows := connectionMutationRowCount(t, database); rows != 1 {
			t.Fatalf("rows after DeleteConnection() = %d, want 1", rows)
		}
		if neighborAfter := fingerprintConnectionMutationRow(t, database, 44); neighborAfter != neighborBefore {
			t.Fatalf("delete changed neighboring row\nbefore=%#v\nafter=%#v", neighborBefore, neighborAfter)
		}
	})
}

func TestCreateConnectionRejectsSealedIntentBeforeDatabaseAccess(t *testing.T) {
	testCases := []struct {
		name       string
		connection *model.ConnectionsDBModel
	}{
		{name: "nil", connection: nil},
		{name: "credential ID", connection: &model.ConnectionsDBModel{CredentialID: "credential"}},
		{name: "credential format", connection: &model.ConnectionsDBModel{CredentialFormat: "format"}},
		{name: "envelope", connection: &model.ConnectionsDBModel{PasswordEnvelope: []byte{0}}},
		{name: "revision", connection: &model.ConnectionsDBModel{RowRevision: 1}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			connections := &connectionsStruct{}
			err := connections.CreateConnection(testCase.connection)
			if !errors.Is(err, ErrSambaConnectionMutationRejected) {
				t.Fatalf("CreateConnection() error = %v, want rejection", err)
			}
		})
	}
}

func TestLegacyConnectionMutationsRejectEveryNonLegacyStorageClass(t *testing.T) {
	const secret = "mutation-secret-must-not-appear"
	variants := []struct {
		name string
		sql  string
	}{
		{name: "credential ID", sql: `UPDATE o_connections SET credential_id = 'credential' WHERE id = 1`},
		{name: "credential format", sql: `UPDATE o_connections SET credential_format = 'format' WHERE id = 1`},
		{name: "nonempty BLOB envelope", sql: `UPDATE o_connections SET password_envelope = X'00' WHERE id = 1`},
		{name: "empty TEXT envelope", sql: `UPDATE o_connections SET password_envelope = '' WHERE id = 1`},
		{name: "nonzero revision", sql: `UPDATE o_connections SET row_revision = 1 WHERE id = 1`},
		{name: "numeric identity", sql: `UPDATE o_connections SET credential_id = 0 WHERE id = 1`},
		{name: "BLOB format", sql: `UPDATE o_connections SET credential_format = X'' WHERE id = 1`},
		{name: "BLOB revision", sql: `UPDATE o_connections SET row_revision = X'30' WHERE id = 1`},
	}
	mutators := []struct {
		name string
		call func(*connectionsStruct) error
	}{
		{
			name: "create",
			call: func(connections *connectionsStruct) error {
				return connections.CreateConnection(&model.ConnectionsDBModel{Username: "new", Password: secret, Host: "new-host", Port: "445"})
			},
		},
		{
			name: "update",
			call: func(connections *connectionsStruct) error {
				return connections.UpdateConnectionMountState(1, "445", "Changed", "changed-boot", "{}")
			},
		},
		{
			name: "delete",
			call: func(connections *connectionsStruct) error {
				return connections.DeleteConnection("1")
			},
		},
	}

	for _, variant := range variants {
		for _, mutator := range mutators {
			t.Run(variant.name+"/"+mutator.name, func(t *testing.T) {
				database := newConnectionMutationTestDatabase(t, "nonlegacy.db", false)
				seedLegacyConnection(t, database, 1)
				if err := database.Exec(variant.sql).Error; err != nil {
					t.Fatalf("prepare nonlegacy row: %v", err)
				}
				before := fingerprintConnectionMutationRow(t, database, 1)
				beforeRows := connectionMutationRowCount(t, database)

				err := mutator.call(&connectionsStruct{db: database})
				if !errors.Is(err, ErrSambaConnectionMutationRejected) {
					t.Fatalf("mutation error = %v, want rejection", err)
				}
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("mutation error leaked secret: %q", err)
				}
				if after := fingerprintConnectionMutationRow(t, database, 1); after != before {
					t.Fatalf("blocked mutation changed row\nbefore=%#v\nafter=%#v", before, after)
				}
				if afterRows := connectionMutationRowCount(t, database); afterRows != beforeRows {
					t.Fatalf("blocked mutation row count = %d, want %d", afterRows, beforeRows)
				}
			})
		}
	}
}

func TestLegacyConnectionMutationsRejectAnyMigrationMarker(t *testing.T) {
	mutators := []struct {
		name string
		call func(*connectionsStruct) error
	}{
		{name: "create", call: func(connections *connectionsStruct) error {
			return connections.CreateConnection(&model.ConnectionsDBModel{Username: "new", Password: "secret", Host: "new", Port: "445"})
		}},
		{name: "update", call: func(connections *connectionsStruct) error {
			return connections.UpdateConnectionMountState(1, "445", "Changed", "boot", "{}")
		}},
		{name: "delete", call: func(connections *connectionsStruct) error {
			return connections.DeleteConnection("1")
		}},
	}

	for _, state := range []string{model.SecurityMigrationPending, model.SecurityMigrationComplete} {
		for _, mutator := range mutators {
			t.Run(state+"/"+mutator.name, func(t *testing.T) {
				database := newConnectionMutationTestDatabase(t, "marker.db", false)
				seedLegacyConnection(t, database, 1)
				if err := database.Exec(
					"INSERT INTO o_security_migrations(name, state, updated) VALUES (?, ?, ?)",
					"unrelated-marker", state, 1,
				).Error; err != nil {
					t.Fatalf("insert marker: %v", err)
				}
				before := fingerprintConnectionMutationRow(t, database, 1)
				err := mutator.call(&connectionsStruct{db: database})
				if !errors.Is(err, ErrSambaConnectionMutationRejected) {
					t.Fatalf("mutation error = %v, want rejection", err)
				}
				if after := fingerprintConnectionMutationRow(t, database, 1); after != before {
					t.Fatalf("marker-blocked mutation changed row\nbefore=%#v\nafter=%#v", before, after)
				}
				if rows := connectionMutationRowCount(t, database); rows != 1 {
					t.Fatalf("marker-blocked mutation row count = %d, want 1", rows)
				}
			})
		}
	}
}

func TestLegacyConnectionMutationRowsAffectedContract(t *testing.T) {
	t.Run("missing update cannot fall back to insert", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "missing-update.db", false)
		err := (&connectionsStruct{db: database}).UpdateConnectionMountState(77, "445", "Media", "boot", "{}")
		if !errors.Is(err, ErrSambaConnectionMutationRejected) {
			t.Fatalf("missing update error = %v, want rejection", err)
		}
		if rows := connectionMutationRowCount(t, database); rows != 0 {
			t.Fatalf("missing update inserted %d rows", rows)
		}
	})

	t.Run("zero ID update rejects before database access", func(t *testing.T) {
		err := (&connectionsStruct{}).UpdateConnectionMountState(0, "445", "Media", "boot", "{}")
		if !errors.Is(err, ErrSambaConnectionMutationRejected) {
			t.Fatalf("zero ID update error = %v, want rejection", err)
		}
	})

	t.Run("missing delete is not silent success", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "missing-delete.db", false)
		err := (&connectionsStruct{db: database}).DeleteConnection("77")
		if !errors.Is(err, ErrSambaConnectionMutationRejected) {
			t.Fatalf("missing delete error = %v, want rejection", err)
		}
	})

	t.Run("trigger ignore is rejected", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "ignore.db", false)
		seedLegacyConnection(t, database, 1)
		if err := database.Exec(`CREATE TRIGGER ignore_connection_update
			BEFORE UPDATE ON o_connections BEGIN SELECT RAISE(IGNORE); END`).Error; err != nil {
			t.Fatalf("create ignore trigger: %v", err)
		}
		before := fingerprintConnectionMutationRow(t, database, 1)
		err := (&connectionsStruct{db: database}).UpdateConnectionMountState(1, "445", "Changed", "boot", "{}")
		if !errors.Is(err, ErrSambaConnectionMutationRejected) {
			t.Fatalf("ignored update error = %v, want rejection", err)
		}
		if after := fingerprintConnectionMutationRow(t, database, 1); after != before {
			t.Fatalf("ignored update changed row\nbefore=%#v\nafter=%#v", before, after)
		}
	})

	t.Run("create trigger ignore is rejected", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "ignore-create.db", false)
		if err := database.Exec(`CREATE TRIGGER ignore_connection_create
			BEFORE INSERT ON o_connections BEGIN SELECT RAISE(IGNORE); END`).Error; err != nil {
			t.Fatalf("create insert-ignore trigger: %v", err)
		}
		err := (&connectionsStruct{db: database}).CreateConnection(&model.ConnectionsDBModel{
			Username: "user",
			Password: "password",
			Host:     "host",
			Port:     "445",
		})
		if !errors.Is(err, ErrSambaConnectionMutationRejected) {
			t.Fatalf("ignored create error = %v, want rejection", err)
		}
		if rows := connectionMutationRowCount(t, database); rows != 0 {
			t.Fatalf("ignored create inserted %d rows", rows)
		}
	})

	t.Run("delete trigger ignore is rejected", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "ignore-delete.db", false)
		seedLegacyConnection(t, database, 1)
		if err := database.Exec(`CREATE TRIGGER ignore_connection_delete
			BEFORE DELETE ON o_connections BEGIN SELECT RAISE(IGNORE); END`).Error; err != nil {
			t.Fatalf("create delete-ignore trigger: %v", err)
		}
		before := fingerprintConnectionMutationRow(t, database, 1)
		err := (&connectionsStruct{db: database}).DeleteConnection("1")
		if !errors.Is(err, ErrSambaConnectionMutationRejected) {
			t.Fatalf("ignored delete error = %v, want rejection", err)
		}
		if after := fingerprintConnectionMutationRow(t, database, 1); after != before {
			t.Fatalf("ignored delete changed row\nbefore=%#v\nafter=%#v", before, after)
		}
	})

	t.Run("database error is static and secret-free", func(t *testing.T) {
		const secret = "trigger-secret-must-not-leak"
		var databaseLogs bytes.Buffer
		productionStyleLogger := logger.New(log.New(&databaseLogs, "", 0), logger.Config{
			SlowThreshold:        2 * time.Second,
			LogLevel:             logger.Warn,
			ParameterizedQueries: true,
			Colorful:             false,
		})
		database := openConnectionMutationTestDatabaseWithLogger(
			t,
			filepath.Join(t.TempDir(), "abort.db"),
			productionStyleLogger,
		)
		createConnectionMutationTestSchema(t, database)
		seedLegacyConnection(t, database, 1)
		if err := database.Exec(`CREATE TRIGGER abort_connection_update
			BEFORE UPDATE ON o_connections BEGIN SELECT RAISE(ABORT, '` + secret + `'); END`).Error; err != nil {
			t.Fatalf("create abort trigger: %v", err)
		}
		databaseLogs.Reset()
		err := (&connectionsStruct{db: database}).UpdateConnectionMountState(1, "445", "Changed", "boot", "{}")
		if !errors.Is(err, ErrSambaConnectionMutationFailed) {
			t.Fatalf("aborted update error = %v, want static failure", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("aborted update leaked trigger text: %q", err)
		}
		if databaseLogs.Len() != 0 {
			t.Fatalf("aborted update reached production database logger: %q", databaseLogs.String())
		}
	})

	t.Run("create constraint error does not expose the password", func(t *testing.T) {
		const secret = "create-password-must-not-leak"
		var databaseLogs bytes.Buffer
		database := openConnectionMutationTestDatabaseWithLogger(
			t,
			filepath.Join(t.TempDir(), "create-constraint.db"),
			logger.New(log.New(&databaseLogs, "", 0), logger.Config{
				SlowThreshold:        2 * time.Second,
				LogLevel:             logger.Warn,
				ParameterizedQueries: true,
				Colorful:             false,
			}),
		)
		createConnectionMutationTestSchema(t, database)
		seedLegacyConnection(t, database, 1)
		connection := &model.ConnectionsDBModel{
			ID:       1,
			Username: "duplicate",
			Password: secret,
			Host:     "duplicate-host",
			Port:     "445",
		}
		databaseLogs.Reset()
		err := (&connectionsStruct{db: database}).CreateConnection(connection)
		if !errors.Is(err, ErrSambaConnectionMutationFailed) {
			t.Fatalf("duplicate create error = %v, want static failure", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("duplicate create leaked password: %q", err)
		}
		if databaseLogs.Len() != 0 {
			t.Fatalf("duplicate create reached production database logger: %q", databaseLogs.String())
		}
	})

	t.Run("more than one affected row rolls back", func(t *testing.T) {
		database := newConnectionMutationTestDatabase(t, "multi-row.db", false)
		seedLegacyConnection(t, database, 1)
		seedLegacyConnection(t, database, 2)
		err := runLegacyConnectionMutation(database, func(transaction *gorm.DB) error {
			result := transaction.Model(&model.ConnectionsDBModel{}).
				Where("id IN ?", []uint{1, 2}).
				UpdateColumn("status", "changed")
			return requireOneSambaConnectionMutation(result)
		})
		if !errors.Is(err, ErrSambaConnectionMutationFailed) {
			t.Fatalf("multi-row mutation error = %v, want failure", err)
		}
		for _, id := range []uint{1, 2} {
			var status string
			if err := database.Raw("SELECT status FROM o_connections WHERE id = ?", id).Scan(&status).Error; err != nil {
				t.Fatalf("read row %d: %v", id, err)
			}
			if status != fmt.Sprintf("status-%d", id) {
				t.Fatalf("row %d status = %q after rollback", id, status)
			}
		}
	})

	t.Run("helper rejects nil zero and multi-row results", func(t *testing.T) {
		if !errors.Is(requireOneSambaConnectionMutation(nil), ErrSambaConnectionMutationFailed) {
			t.Fatal("nil result was not rejected")
		}
		if !errors.Is(requireOneSambaConnectionMutation(&gorm.DB{}), ErrSambaConnectionMutationRejected) {
			t.Fatal("zero-row result was not rejected")
		}
		if !errors.Is(requireOneSambaConnectionMutation(&gorm.DB{RowsAffected: 2}), ErrSambaConnectionMutationFailed) {
			t.Fatal("multi-row result was not rejected")
		}
		if err := requireOneSambaConnectionMutation(&gorm.DB{RowsAffected: 1}); err != nil {
			t.Fatalf("one-row result error = %v", err)
		}
	})

	t.Run("wrapped rejection is canonicalized", func(t *testing.T) {
		const secret = "wrapped-rejection-secret"
		database := newConnectionMutationTestDatabase(t, "wrapped-rejection.db", false)
		err := runLegacyConnectionMutation(database, func(*gorm.DB) error {
			return fmt.Errorf("%s: %w", secret, ErrSambaConnectionMutationRejected)
		})
		if err != ErrSambaConnectionMutationRejected {
			t.Fatalf("wrapped rejection error = %v, want canonical sentinel", err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("wrapped rejection leaked text: %q", err)
		}
	})
}

func TestLegacyConnectionMutationSQLShapeOmitsSealedColumns(t *testing.T) {
	database := newConnectionMutationTestDatabase(t, "shape.db", false).
		Session(&gorm.Session{DryRun: true, SkipDefaultTransaction: true})
	connection := &model.ConnectionsDBModel{
		Username:         "alice",
		Password:         "secret",
		CredentialID:     "must-not-be-inserted",
		CredentialFormat: "must-not-be-inserted",
		PasswordEnvelope: []byte("must-not-be-inserted"),
		RowRevision:      9,
		Host:             "nas",
		Port:             "445",
	}

	createSQL := createLegacyConnectionRecord(database, connection).Statement.SQL.String()
	createColumns := strings.SplitN(createSQL, "VALUES", 2)[0]
	for _, forbidden := range []string{"credential_id", "credential_format", "password_envelope", "row_revision"} {
		if strings.Contains(createColumns, forbidden) {
			t.Fatalf("create SQL includes sealed column %q: %s", forbidden, createSQL)
		}
	}

	assertGuardedWhere := func(operation, statement string) string {
		t.Helper()
		parts := strings.SplitN(statement, "WHERE", 2)
		if len(parts) != 2 {
			t.Fatalf("%s SQL has no WHERE clause: %s", operation, statement)
		}
		normalizedWhere := strings.Join(strings.Fields(parts[1]), " ")
		for description, required := range map[string]string{
			"target ID":        "id = ?",
			"legacy predicate": strings.Join(strings.Fields(model.LegacySMBCredentialRowPredicateSQL), " "),
			"marker fence":     "NOT EXISTS (SELECT 1 FROM o_security_migrations)",
		} {
			if !strings.Contains(normalizedWhere, required) {
				t.Fatalf("%s WHERE omits %s: %s", operation, description, statement)
			}
		}
		return parts[0]
	}

	updateSQL := updateLegacyConnectionMountStateRecord(database, 1, "445", "Media", "boot", "{}").Statement.SQL.String()
	updateSet := assertGuardedWhere("update", updateSQL)
	for _, forbidden := range []string{"username", "password", "credential_id", "credential_format", "password_envelope", "row_revision", "host", "status", "mount_point", "created"} {
		if strings.Contains(updateSet, forbidden) {
			t.Fatalf("update SET includes forbidden column %q: %s", forbidden, updateSQL)
		}
	}
	for _, required := range []string{"updated", "port", "directories", "boot_id", "mount_ids"} {
		if !strings.Contains(updateSet, required) {
			t.Fatalf("update SET omits required column %q: %s", required, updateSQL)
		}
	}

	deleteSQL := deleteLegacyConnectionRecord(database, "1").Statement.SQL.String()
	deletePrefix := assertGuardedWhere("delete", deleteSQL)
	if !strings.Contains(deletePrefix, "DELETE FROM") {
		t.Fatalf("delete SQL is not a DELETE statement: %s", deleteSQL)
	}
}

func TestLegacyConnectionMutationSnapshotRejectsConcurrentMarker(t *testing.T) {
	testCases := []struct {
		name   string
		mutate func(*gorm.DB) error
	}{
		{
			name: "create",
			mutate: func(transaction *gorm.DB) error {
				return requireOneSambaConnectionMutation(createLegacyConnectionRecord(
					transaction,
					&model.ConnectionsDBModel{Username: "new", Password: "secret", Host: "new-host", Port: "445"},
				))
			},
		},
		{
			name: "update",
			mutate: func(transaction *gorm.DB) error {
				return requireOneSambaConnectionMutation(updateLegacyConnectionMountStateRecord(
					transaction, 1, "445", "Changed", "new-boot", "{}",
				))
			},
		},
		{
			name: "delete",
			mutate: func(transaction *gorm.DB) error {
				return requireOneSambaConnectionMutation(deleteLegacyConnectionRecord(transaction, "1"))
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			databasePath := filepath.Join(t.TempDir(), "marker-race.db")
			databaseA := openConnectionMutationTestDatabase(t, databasePath)
			createConnectionMutationTestSchema(t, databaseA)
			seedLegacyConnection(t, databaseA, 1)
			seedLegacyConnection(t, databaseA, 2)

			var firstMode string
			if err := databaseA.Raw("PRAGMA journal_mode = WAL").Scan(&firstMode).Error; err != nil {
				t.Fatalf("enable WAL on first handle: %v", err)
			}
			if !strings.EqualFold(firstMode, "wal") {
				t.Skipf("WAL journal mode is unavailable: %q", firstMode)
			}
			databaseB := openConnectionMutationTestDatabase(t, databasePath)
			var secondMode string
			if err := databaseB.Raw("PRAGMA journal_mode").Scan(&secondMode).Error; err != nil {
				t.Fatalf("read WAL mode on second handle: %v", err)
			}
			if !strings.EqualFold(secondMode, "wal") {
				t.Fatalf("second handle journal mode = %q, want wal", secondMode)
			}
			if err := databaseA.Exec("PRAGMA busy_timeout = 1000").Error; err != nil {
				t.Fatalf("set first busy timeout: %v", err)
			}
			if err := databaseB.Exec("PRAGMA busy_timeout = 1000").Error; err != nil {
				t.Fatalf("set second busy timeout: %v", err)
			}

			beforeRows := connectionMutationRowCount(t, databaseA)
			firstBefore := fingerprintConnectionMutationRow(t, databaseA, 1)
			secondBefore := fingerprintConnectionMutationRow(t, databaseA, 2)
			preflightComplete := make(chan struct{})
			markerCommitted := make(chan struct{})
			result := make(chan error, 1)
			markerReleased := false
			defer func() {
				if !markerReleased {
					close(markerCommitted)
				}
			}()
			go func() {
				result <- runLegacyConnectionMutation(databaseA, func(transaction *gorm.DB) error {
					close(preflightComplete)
					<-markerCommitted
					return testCase.mutate(transaction)
				})
			}()

			select {
			case <-preflightComplete:
			case err := <-result:
				t.Fatalf("mutation ended before the preflight checkpoint: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the preflight checkpoint")
			}
			markerErr := databaseB.Exec(
				"INSERT INTO o_security_migrations(name, state, updated) VALUES (?, ?, ?)",
				model.SMBCredentialMigrationName, model.SecurityMigrationPending, 1,
			).Error
			close(markerCommitted)
			markerReleased = true
			if markerErr != nil {
				t.Fatalf("commit concurrent marker: %v", markerErr)
			}

			select {
			case err := <-result:
				if !errors.Is(err, ErrSambaConnectionMutationFailed) {
					t.Fatalf("snapshot-conflicted mutation error = %v, want static failure", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out waiting for the snapshot-conflicted mutation")
			}
			if rows := connectionMutationRowCount(t, databaseB); rows != beforeRows {
				t.Fatalf("rows after marker race = %d, want %d", rows, beforeRows)
			}
			if firstAfter := fingerprintConnectionMutationRow(t, databaseB, 1); firstAfter != firstBefore {
				t.Fatalf("marker race changed target row\nbefore=%#v\nafter=%#v", firstBefore, firstAfter)
			}
			if secondAfter := fingerprintConnectionMutationRow(t, databaseB, 2); secondAfter != secondBefore {
				t.Fatalf("marker race changed neighboring row\nbefore=%#v\nafter=%#v", secondBefore, secondAfter)
			}
			var markers int64
			if err := databaseB.Raw("SELECT count(*) FROM o_security_migrations").Scan(&markers).Error; err != nil {
				t.Fatalf("count marker after race: %v", err)
			}
			if markers != 1 {
				t.Fatalf("markers after race = %d, want 1", markers)
			}
		})
	}
}

func newConnectionMutationTestDatabase(t *testing.T, name string, wal bool) *gorm.DB {
	t.Helper()
	database := openConnectionMutationTestDatabase(t, filepath.Join(t.TempDir(), name))
	createConnectionMutationTestSchema(t, database)
	if wal {
		if err := database.Exec("PRAGMA journal_mode = WAL").Error; err != nil {
			t.Fatalf("enable WAL: %v", err)
		}
	}
	return database
}

func openConnectionMutationTestDatabase(t *testing.T, path string) *gorm.DB {
	t.Helper()
	return openConnectionMutationTestDatabaseWithLogger(t, path, logger.Default.LogMode(logger.Silent))
}

func openConnectionMutationTestDatabaseWithLogger(t *testing.T, path string, databaseLogger logger.Interface) *gorm.DB {
	t.Helper()
	database, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		NowFunc: func() time.Time { return connectionMutationTestNow },
		Logger:  databaseLogger,
	})
	if err != nil {
		t.Fatalf("gorm.Open(%q): %v", path, err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatalf("database.DB(): %v", err)
	}
	sqlDatabase.SetMaxOpenConns(1)
	t.Cleanup(func() {
		if err := sqlDatabase.Close(); err != nil {
			t.Errorf("close database: %v", err)
		}
	})
	return database
}

func createConnectionMutationTestSchema(t *testing.T, database *gorm.DB) {
	t.Helper()
	if err := database.Exec(connectionMutationTestSchema).Error; err != nil {
		t.Fatalf("create connection mutation schema: %v", err)
	}
}

func seedLegacyConnection(t *testing.T, database *gorm.DB, id uint) {
	t.Helper()
	if err := database.Exec(`INSERT INTO o_connections(
		id, updated, created, username, password, credential_id,
		credential_format, password_envelope, row_revision, host, port,
		status, directories, mount_point, boot_id, mount_ids
	) VALUES (?, ?, ?, ?, ?, '', '', X'', 0, ?, ?, ?, ?, ?, ?, ?)`,
		id,
		102,
		101,
		fmt.Sprintf("user-%d", id),
		fmt.Sprintf("password-%d", id),
		fmt.Sprintf("host-%d", id),
		"1445",
		fmt.Sprintf("status-%d", id),
		"Media",
		fmt.Sprintf("/mnt/host-%d", id),
		"boot-old",
		fmt.Sprintf(`{"Media":%d}`, id),
	).Error; err != nil {
		t.Fatalf("seed legacy connection %d: %v", id, err)
	}
}

func connectionMutationRowCount(t *testing.T, database *gorm.DB) int64 {
	t.Helper()
	var rows int64
	if err := database.Raw("SELECT count(*) FROM o_connections").Scan(&rows).Error; err != nil {
		t.Fatalf("count connection rows: %v", err)
	}
	return rows
}

func fingerprintConnectionMutationRow(t *testing.T, database *gorm.DB, id uint) connectionMutationFingerprint {
	t.Helper()
	var fingerprint connectionMutationFingerprint
	if err := database.Raw(`SELECT
		printf('%s:%s', typeof(id), quote(id)) AS id,
		printf('%s:%s', typeof(updated), quote(updated)) AS updated,
		printf('%s:%s', typeof(created), quote(created)) AS created,
		printf('%s:%s', typeof(username), quote(username)) AS username,
		printf('%s:%s', typeof(password), quote(password)) AS password,
		printf('%s:%s', typeof(credential_id), quote(credential_id)) AS credential_id,
		printf('%s:%s', typeof(credential_format), quote(credential_format)) AS credential_format,
		printf('%s:%s', typeof(password_envelope), quote(password_envelope)) AS password_envelope,
		printf('%s:%s', typeof(row_revision), quote(row_revision)) AS row_revision,
		printf('%s:%s', typeof(host), quote(host)) AS host,
		printf('%s:%s', typeof(port), quote(port)) AS port,
		printf('%s:%s', typeof(status), quote(status)) AS status,
		printf('%s:%s', typeof(directories), quote(directories)) AS directories,
		printf('%s:%s', typeof(mount_point), quote(mount_point)) AS mount_point,
		printf('%s:%s', typeof(boot_id), quote(boot_id)) AS boot_id,
		printf('%s:%s', typeof(mount_ids), quote(mount_ids)) AS mount_ids
		FROM o_connections WHERE id = ?`, id).Scan(&fingerprint).Error; err != nil {
		t.Fatalf("fingerprint connection %d: %v", id, err)
	}
	return fingerprint
}

func assertConnectionCredentialStorageTypes(t *testing.T, database *gorm.DB, id uint, credentialID, credentialFormat, envelope, revision string) {
	t.Helper()
	var storage struct {
		CredentialID     string
		CredentialFormat string
		Envelope         string
		Revision         string
	}
	if err := database.Raw(`SELECT
		typeof(credential_id) AS credential_id,
		typeof(credential_format) AS credential_format,
		typeof(password_envelope) AS envelope,
		typeof(row_revision) AS revision
		FROM o_connections WHERE id = ?`, id).Scan(&storage).Error; err != nil {
		t.Fatalf("inspect credential storage types: %v", err)
	}
	if storage.CredentialID != credentialID || storage.CredentialFormat != credentialFormat || storage.Envelope != envelope || storage.Revision != revision {
		t.Fatalf("credential storage types = (%s, %s, %s, %s), want (%s, %s, %s, %s)",
			storage.CredentialID, storage.CredentialFormat, storage.Envelope, storage.Revision,
			credentialID, credentialFormat, envelope, revision,
		)
	}
}
