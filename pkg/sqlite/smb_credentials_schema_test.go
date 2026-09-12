package sqlite

import (
	"bytes"
	"database/sql"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	glebarezsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type legacyConnectionsDBModel struct {
	ID          uint  `gorm:"column:id;primary_key"`
	Updated     int64 `gorm:"autoUpdateTime"`
	Created     int64 `gorm:"autoCreateTime"`
	Username    string
	Password    string
	Host        string
	Port        string
	Status      string
	Directories string
	MountPoint  string
	BootID      string
	MountIDs    string
}

type sqliteSchemaObject struct {
	Type      string `gorm:"column:type"`
	Name      string `gorm:"column:name"`
	TableName string `gorm:"column:tbl_name"`
	SQL       string `gorm:"column:sql"`
}

func (*legacyConnectionsDBModel) TableName() string {
	return "o_connections"
}

func TestSMBCredentialSchemaExpandPreservesLegacyRowsAndIsIdempotent(t *testing.T) {
	database := openSMBCredentialSchemaTestDatabase(t)
	if err := database.AutoMigrate(&legacyConnectionsDBModel{}); err != nil {
		t.Fatal(err)
	}
	const password = "legacy-password-must-remain-byte-exact"
	legacy := legacyConnectionsDBModel{
		ID:          17,
		Username:    "legacy-user",
		Password:    password,
		Host:        "nas.internal",
		Port:        "",
		Directories: "photos,backup$",
		MountPoint:  "/mnt/nas.internal",
	}
	if err := database.Create(&legacy).Error; err != nil {
		t.Fatal(err)
	}

	for attempt := 0; attempt < 2; attempt++ {
		if err := expandSMBCredentialSchema(database); err != nil {
			t.Fatalf("expand attempt %d: %v", attempt+1, err)
		}
	}

	var persistedPassword string
	var credentialID sql.NullString
	var credentialFormat sql.NullString
	var passwordEnvelope []byte
	var rowRevision uint64
	row := database.Raw(`SELECT password, credential_id, credential_format, password_envelope, row_revision
		FROM o_connections WHERE id = ?`, legacy.ID).Row()
	if err := row.Scan(&persistedPassword, &credentialID, &credentialFormat, &passwordEnvelope, &rowRevision); err != nil {
		t.Fatal(err)
	}
	if persistedPassword != password || credentialID.Valid || credentialFormat.Valid || passwordEnvelope != nil || rowRevision != 0 {
		t.Fatalf("legacy row changed during expand: password_equal=%t credential_id=%v format=%v envelope_len=%d revision=%d",
			persistedPassword == password, credentialID, credentialFormat, len(passwordEnvelope), rowRevision)
	}
	var markerCount int64
	if err := database.Model(&model2.SecurityMigrationDBModel{}).Count(&markerCount).Error; err != nil {
		t.Fatal(err)
	}
	if markerCount != 0 {
		t.Fatalf("schema expansion created %d migration markers", markerCount)
	}
}

func TestSMBCredentialSchemaMechanicallyExpandsHistoricalDDLAndPreservesObjects(t *testing.T) {
	database := openSMBCredentialSchemaTestDatabase(t)
	createHistoricalConnectionsSchema(t, database)
	const password = "historical-password-byte-sentinel"
	if err := database.Exec(`INSERT INTO o_connections(
		id, updated, created, username, password, host, port, status, directories, mount_point
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		41, 100, 90, "historical-user", password, "legacy.internal", "", "ready", "photos", "/mnt/legacy.internal",
	).Error; err != nil {
		t.Fatal(err)
	}
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatal(err)
	}

	var persisted legacyConnectionsDBModel
	if err := database.First(&persisted, 41).Error; err != nil {
		t.Fatal(err)
	}
	if persisted.Password != password || persisted.Username != "historical-user" || persisted.Host != "legacy.internal" || persisted.Directories != "photos" {
		t.Fatalf("historical row changed during mechanical expansion: %#v", persisted)
	}
	if err := database.Exec("UPDATE o_connections SET status = ? WHERE id = ?", "blocked", 41).Error; err == nil {
		t.Fatal("historical trigger was discarded during expansion")
	}
	assertSchemaObjectCount(t, database, "index", "idx_o_connections_host_legacy", 1)

	beforeVersion := sqliteSchemaVersion(t, database)
	beforeObjects := sqliteSchemaObjects(t, database)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatalf("second expansion: %v", err)
	}
	if afterVersion := sqliteSchemaVersion(t, database); afterVersion != beforeVersion {
		t.Fatalf("idempotent expansion changed schema_version from %d to %d", beforeVersion, afterVersion)
	}
	if afterObjects := sqliteSchemaObjects(t, database); !reflect.DeepEqual(afterObjects, beforeObjects) {
		t.Fatalf("idempotent expansion changed sqlite_master:\nbefore=%#v\nafter=%#v", beforeObjects, afterObjects)
	}
}

func TestSMBCredentialIdentityIndexAllowsLegacyRowsAndRejectsDuplicateSealedIdentity(t *testing.T) {
	database := openSMBCredentialSchemaTestDatabase(t)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatal(err)
	}
	for index, credentialID := range []any{nil, nil, "", "", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"} {
		result := database.Exec(
			"INSERT INTO o_connections(id, username, password, credential_id, row_revision) VALUES (?, ?, ?, ?, ?)",
			index+1,
			"user",
			"legacy",
			credentialID,
			0,
		)
		if result.Error != nil {
			t.Fatalf("insert credential identity %v: %v", credentialID, result.Error)
		}
	}
	duplicate := database.Exec(
		"INSERT INTO o_connections(id, username, password, credential_id, row_revision) VALUES (?, ?, ?, ?, ?)",
		99,
		"user",
		"legacy",
		"11111111-1111-4111-8111-111111111111",
		1,
	)
	if duplicate.Error == nil {
		t.Fatal("duplicate non-empty credential identity unexpectedly succeeded")
	}
	var rows int64
	if err := database.Model(&model2.ConnectionsDBModel{}).Count(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if rows != 6 {
		t.Fatalf("duplicate insert changed row count to %d", rows)
	}
}

func TestSecurityMigrationTableAcceptsOnlyExplicitStates(t *testing.T) {
	database := openSMBCredentialSchemaTestDatabase(t)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatal(err)
	}
	marker := model2.SecurityMigrationDBModel{
		Name:    model2.SMBCredentialMigrationName,
		State:   model2.SecurityMigrationPending,
		Updated: 1,
	}
	if err := database.Create(&marker).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Model(&marker).Update("state", model2.SecurityMigrationComplete).Error; err != nil {
		t.Fatal(err)
	}
	var persistedState string
	if err := database.Raw("SELECT state FROM o_security_migrations WHERE name = ?", model2.SMBCredentialMigrationName).Scan(&persistedState).Error; err != nil {
		t.Fatal(err)
	}
	if persistedState != model2.SecurityMigrationComplete {
		t.Fatalf("persisted migration state = %q, want %q", persistedState, model2.SecurityMigrationComplete)
	}
	if err := database.Create(&marker).Error; err == nil {
		t.Fatal("duplicate security migration name unexpectedly succeeded")
	}
	for name, statement := range map[string]string{
		"NULL name":  "INSERT INTO o_security_migrations(name, state, updated) VALUES (NULL, 'pending', 1)",
		"NULL state": "INSERT INTO o_security_migrations(name, state, updated) VALUES ('null-state', NULL, 1)",
	} {
		if err := database.Exec(statement).Error; err == nil {
			t.Fatalf("%s unexpectedly succeeded", name)
		}
	}
	if err := database.Exec(
		"INSERT INTO o_security_migrations(name, state, updated) VALUES (?, ?, ?)",
		"invalid-state",
		"unknown",
		1,
	).Error; err == nil {
		t.Fatal("unknown security migration state unexpectedly succeeded")
	}
	if err := database.Exec(
		"INSERT INTO o_security_migrations(name, state, updated) VALUES (?, ?, NULL)",
		"missing-updated",
		model2.SecurityMigrationPending,
	).Error; err == nil {
		t.Fatal("NULL security migration timestamp unexpectedly succeeded")
	}
}

func TestSMBCredentialSchemaExpandRefusesSealedPartialAndMigrationMarkedState(t *testing.T) {
	tests := map[string]func(*testing.T, *gorm.DB){
		"credential identity": func(t *testing.T, database *gorm.DB) {
			insertCredentialStateFixture(t, database, "11111111-1111-4111-8111-111111111111", "", nil, 0)
		},
		"credential format": func(t *testing.T, database *gorm.DB) {
			insertCredentialStateFixture(t, database, "", "recasaos-smb-envelope-v1", nil, 0)
		},
		"password envelope": func(t *testing.T, database *gorm.DB) {
			insertCredentialStateFixture(t, database, "", "", []byte{1}, 0)
		},
		"NUL-prefixed text envelope": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.Exec(`INSERT INTO o_connections(
				id, username, password, credential_id, credential_format, password_envelope, row_revision
			) VALUES (?, ?, ?, ?, ?, char(0) || ?, ?)`, 1, "user", "legacy", "", "", "ciphertext", 0).Error; err != nil {
				t.Fatal(err)
			}
		},
		"row revision": func(t *testing.T, database *gorm.DB) {
			insertCredentialStateFixture(t, database, "", "", nil, 1)
		},
		"migration marker": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.Create(&model2.SecurityMigrationDBModel{
				Name:    model2.SMBCredentialMigrationName,
				State:   model2.SecurityMigrationPending,
				Updated: 1,
			}).Error; err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			database := openSMBCredentialSchemaTestDatabase(t)
			if err := expandSMBCredentialSchema(database); err != nil {
				t.Fatal(err)
			}
			arrange(t, database)
			if err := expandSMBCredentialSchema(database); err == nil {
				t.Fatal("non-legacy credential state unexpectedly accepted")
			}
		})
	}
}

func TestSMBCredentialSchemaExpandAcceptsExplicitlyEmptyLegacyState(t *testing.T) {
	database := openSMBCredentialSchemaTestDatabase(t)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatal(err)
	}
	insertCredentialStateFixture(t, database, "", "", []byte{}, 0)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatalf("explicit empty legacy state rejected: %v", err)
	}
}

func TestSMBCredentialSchemaRejectsConflictingPreexistingObjects(t *testing.T) {
	tests := map[string]func(*testing.T, *gorm.DB){
		"marker table without state constraint": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.AutoMigrate(&model2.ConnectionsDBModel{}); err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(`CREATE TABLE o_security_migrations (
				name TEXT NOT NULL PRIMARY KEY,
				state TEXT NOT NULL,
				updated INTEGER NOT NULL
			) WITHOUT ROWID`).Error; err != nil {
				t.Fatal(err)
			}
		},
		"marker table with wrong-case states": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.AutoMigrate(&model2.ConnectionsDBModel{}); err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(`CREATE TABLE o_security_migrations (
				name TEXT NOT NULL PRIMARY KEY,
				state TEXT NOT NULL CHECK (state IN ('PENDING', 'COMPLETE')),
				updated INTEGER NOT NULL
			) WITHOUT ROWID`).Error; err != nil {
				t.Fatal(err)
			}
		},
		"index with weaker predicate": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.AutoMigrate(&model2.ConnectionsDBModel{}); err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(`CREATE UNIQUE INDEX ux_o_connections_credential_id
				ON o_connections(credential_id)
				WHERE credential_id IS NOT NULL`).Error; err != nil {
				t.Fatal(err)
			}
		},
		"duplicate non-empty credential identities": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.AutoMigrate(&model2.ConnectionsDBModel{}); err != nil {
				t.Fatal(err)
			}
			for id := 1; id <= 2; id++ {
				if err := database.Exec(
					"INSERT INTO o_connections(id, credential_id, row_revision) VALUES (?, ?, ?)",
					id,
					"11111111-1111-4111-8111-111111111111",
					1,
				).Error; err != nil {
					t.Fatal(err)
				}
			}
		},
		"row revision with quoted text default": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.Exec(`CREATE TABLE o_connections (
				id INTEGER PRIMARY KEY,
				updated INTEGER,
				created INTEGER,
				username TEXT,
				password TEXT,
				host TEXT,
				port TEXT,
				status TEXT,
				directories TEXT,
				mount_point TEXT,
				boot_id TEXT,
				mount_ids TEXT,
				credential_id TEXT,
				credential_format TEXT,
				password_envelope BLOB,
				row_revision INTEGER NOT NULL DEFAULT '''0'''
			)`).Error; err != nil {
				t.Fatal(err)
			}
		},
		"descending integer primary key": func(t *testing.T, database *gorm.DB) {
			t.Helper()
			if err := database.Exec(`CREATE TABLE o_connections (
				id INTEGER PRIMARY KEY DESC,
				updated INTEGER,
				created INTEGER,
				username TEXT,
				password TEXT,
				host TEXT,
				port TEXT,
				status TEXT,
				directories TEXT,
				mount_point TEXT
			)`).Error; err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			database := openSMBCredentialSchemaTestDatabase(t)
			arrange(t, database)
			err := expandSMBCredentialSchema(database)
			if err == nil {
				t.Fatal("conflicting schema object unexpectedly accepted")
			}
			if strings.Contains(err.Error(), "11111111-1111-4111-8111-111111111111") {
				t.Fatalf("schema error exposed row data: %v", err)
			}
		})
	}
}

func TestSMBCredentialSchemaRejectsNilDatabase(t *testing.T) {
	if err := expandSMBCredentialSchema(nil); err == nil {
		t.Fatal("nil database unexpectedly accepted")
	}
}

func TestSMBCredentialSchemaExpansionRollsBackLateFailuresOnDisk(t *testing.T) {
	t.Run("legacy additions rollback after marker conflict", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rollback.db")
		database, handle := openSMBCredentialSchemaDatabaseAt(t, path)
		createHistoricalConnectionsSchema(t, database)
		if err := database.Exec("INSERT INTO o_connections(id, username, password) VALUES (?, ?, ?)", 7, "user", "preserve-me").Error; err != nil {
			t.Fatal(err)
		}
		if err := database.Exec(`CREATE TABLE o_security_migrations (
			name TEXT NOT NULL PRIMARY KEY,
			state TEXT NOT NULL,
			updated INTEGER NOT NULL
		) WITHOUT ROWID`).Error; err != nil {
			t.Fatal(err)
		}
		if err := expandSMBCredentialSchema(database); err == nil {
			t.Fatal("conflicting marker table unexpectedly accepted")
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		database, handle = openSMBCredentialSchemaDatabaseAt(t, path)
		defer closeSMBCredentialSchemaDatabase(t, handle)
		assertConnectionColumns(t, database, []string{"id", "updated", "created", "username", "password", "host", "port", "status", "directories", "mount_point"})
		assertSchemaObjectCount(t, database, "index", smbCredentialIDIndexName, 0)
		assertSchemaObjectCount(t, database, "index", "idx_o_connections_host_legacy", 1)
		assertSchemaObjectCount(t, database, "trigger", "trg_o_connections_status_legacy", 1)
		var password string
		if err := database.Raw("SELECT password FROM o_connections WHERE id = ?", 7).Scan(&password).Error; err != nil {
			t.Fatal(err)
		}
		if password != "preserve-me" {
			t.Fatalf("rollback changed legacy password: equal=%t", password == "preserve-me")
		}
	})

	t.Run("fresh table rollback after marker conflict", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rollback.db")
		database, handle := openSMBCredentialSchemaDatabaseAt(t, path)
		if err := database.Exec(`CREATE TABLE o_security_migrations (
			name TEXT NOT NULL PRIMARY KEY,
			state TEXT NOT NULL,
			updated INTEGER NOT NULL
		) WITHOUT ROWID`).Error; err != nil {
			t.Fatal(err)
		}
		if err := expandSMBCredentialSchema(database); err == nil {
			t.Fatal("conflicting marker table unexpectedly accepted")
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		database, handle = openSMBCredentialSchemaDatabaseAt(t, path)
		defer closeSMBCredentialSchemaDatabase(t, handle)
		assertSchemaObjectCount(t, database, "table", "o_connections", 0)
		assertSchemaObjectCount(t, database, "index", smbCredentialIDIndexName, 0)
		assertSchemaObjectCount(t, database, "table", "o_security_migrations", 1)
	})

	t.Run("late legacy-only gate rolls back new objects", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rollback.db")
		database, handle := openSMBCredentialSchemaDatabaseAt(t, path)
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
		envelope := []byte{0, 1, 2, 3, 4}
		if err := database.Exec(`INSERT INTO o_connections(
			id, username, password, credential_id, credential_format, password_envelope, row_revision
		) VALUES (?, ?, ?, ?, ?, ?, ?)`, 9, "user", "", "11111111-1111-4111-8111-111111111111", "recasaos-smb-envelope-v1", envelope, 1).Error; err != nil {
			t.Fatal(err)
		}
		if err := expandSMBCredentialSchema(database); err == nil {
			t.Fatal("sealed state unexpectedly accepted")
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		database, handle = openSMBCredentialSchemaDatabaseAt(t, path)
		defer closeSMBCredentialSchemaDatabase(t, handle)
		assertSchemaObjectCount(t, database, "table", "o_security_migrations", 0)
		assertSchemaObjectCount(t, database, "index", smbCredentialIDIndexName, 0)
		var persisted []byte
		if err := database.Raw("SELECT password_envelope FROM o_connections WHERE id = ?", 9).Row().Scan(&persisted); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(persisted, envelope) {
			t.Fatalf("rollback changed envelope: got=%x", persisted)
		}
	})

	t.Run("partial credential schema is not repaired", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rollback.db")
		database, handle := openSMBCredentialSchemaDatabaseAt(t, path)
		createHistoricalConnectionsSchema(t, database)
		if err := database.Exec(addCredentialIDSQL).Error; err != nil {
			t.Fatal(err)
		}
		if err := expandSMBCredentialSchema(database); err == nil {
			t.Fatal("partial credential schema unexpectedly accepted")
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		database, handle = openSMBCredentialSchemaDatabaseAt(t, path)
		defer closeSMBCredentialSchemaDatabase(t, handle)
		assertConnectionColumns(t, database, []string{"id", "updated", "created", "username", "password", "host", "port", "status", "directories", "mount_point", "credential_id"})
		assertSchemaObjectCount(t, database, "table", "o_security_migrations", 0)
		assertSchemaObjectCount(t, database, "index", smbCredentialIDIndexName, 0)
	})

	t.Run("duplicate identity index failure rolls back marker", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rollback.db")
		database, handle := openSMBCredentialSchemaDatabaseAt(t, path)
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
		for id := 1; id <= 2; id++ {
			if err := database.Exec(
				"INSERT INTO o_connections(id, credential_id, row_revision) VALUES (?, ?, ?)",
				id,
				"11111111-1111-4111-8111-111111111111",
				1,
			).Error; err != nil {
				t.Fatal(err)
			}
		}
		if err := expandSMBCredentialSchema(database); err == nil {
			t.Fatal("duplicate credential identities unexpectedly accepted")
		}
		closeSMBCredentialSchemaDatabase(t, handle)

		database, handle = openSMBCredentialSchemaDatabaseAt(t, path)
		defer closeSMBCredentialSchemaDatabase(t, handle)
		assertSchemaObjectCount(t, database, "table", "o_security_migrations", 0)
		assertSchemaObjectCount(t, database, "index", smbCredentialIDIndexName, 0)
		var rows int64
		if err := database.Raw("SELECT count(*) FROM o_connections").Scan(&rows).Error; err != nil {
			t.Fatal(err)
		}
		if rows != 2 {
			t.Fatalf("index failure changed row count to %d", rows)
		}
	})
}

func openSMBCredentialSchemaTestDatabase(t *testing.T) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "schema.db")
	database, sqlDatabase := openSMBCredentialSchemaDatabaseAt(t, path)
	t.Cleanup(func() { closeSMBCredentialSchemaDatabase(t, sqlDatabase) })
	return database
}

func openSMBCredentialSchemaDatabaseAt(t *testing.T, path string) (*gorm.DB, *sql.DB) {
	t.Helper()
	database, err := gorm.Open(glebarezsqlite.Open(path), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	sqlDatabase.SetMaxOpenConns(1)
	return database, sqlDatabase
}

func closeSMBCredentialSchemaDatabase(t *testing.T, database *sql.DB) {
	t.Helper()
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func insertCredentialStateFixture(t *testing.T, database *gorm.DB, credentialID, credentialFormat string, envelope []byte, revision uint64) {
	t.Helper()
	if err := database.Exec(`INSERT INTO o_connections(
		id, username, password, credential_id, credential_format, password_envelope, row_revision
	) VALUES (?, ?, ?, ?, ?, ?, ?)`, 1, "user", "legacy", credentialID, credentialFormat, envelope, revision).Error; err != nil {
		t.Fatal(err)
	}
}

func createHistoricalConnectionsSchema(t *testing.T, database *gorm.DB) {
	t.Helper()
	for _, statement := range []string{
		`CREATE TABLE "o_connections" (
			"id" INTEGER PRIMARY KEY AUTOINCREMENT,
			"updated" INTEGER,
			"created" INTEGER,
			"username" TEXT,
			"password" TEXT,
			"host" TEXT,
			"port" TEXT,
			"status" TEXT,
			"directories" TEXT,
			"mount_point" TEXT
		)`,
		`CREATE INDEX idx_o_connections_host_legacy ON o_connections(host)`,
		`CREATE TRIGGER trg_o_connections_status_legacy
			BEFORE UPDATE OF status ON o_connections
			WHEN NEW.status = 'blocked'
			BEGIN
				SELECT RAISE(ABORT, 'legacy status guard');
			END`,
	} {
		if err := database.Exec(statement).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func sqliteSchemaVersion(t *testing.T, database *gorm.DB) int64 {
	t.Helper()
	var version int64
	if err := database.Raw("PRAGMA schema_version").Scan(&version).Error; err != nil {
		t.Fatal(err)
	}
	return version
}

func sqliteSchemaObjects(t *testing.T, database *gorm.DB) []sqliteSchemaObject {
	t.Helper()
	var objects []sqliteSchemaObject
	if err := database.Raw(`SELECT type, name, tbl_name, sql FROM sqlite_master
		WHERE name NOT LIKE 'sqlite_%' AND sql IS NOT NULL
		ORDER BY type, name`).Scan(&objects).Error; err != nil {
		t.Fatal(err)
	}
	return objects
}

func assertSchemaObjectCount(t *testing.T, database *gorm.DB, objectType, name string, expected int64) {
	t.Helper()
	var count int64
	if err := database.Raw("SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?", objectType, name).Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("sqlite_master %s %s count = %d, want %d", objectType, name, count, expected)
	}
}

func assertConnectionColumns(t *testing.T, database *gorm.DB, expected []string) {
	t.Helper()
	var columns []sqliteTableColumn
	if err := database.Raw("PRAGMA table_info('o_connections')").Scan(&columns).Error; err != nil {
		t.Fatal(err)
	}
	actual := make([]string, 0, len(columns))
	for _, column := range columns {
		actual = append(actual, column.Name)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("o_connections columns = %v, want %v", actual, expected)
	}
}
