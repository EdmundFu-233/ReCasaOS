package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/IceWhaleTech/CasaOS/pkg/smbcredentials"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	glebarezsqlite "github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type cutoverTestCredential struct {
	ID          int64
	Username    string
	Password    string
	Host        string
	Port        string
	Directories string
	BootID      string
	MountIDs    string
}

type cutoverTestStoredRow struct {
	ID               int64          `gorm:"column:id"`
	Username         string         `gorm:"column:username"`
	Password         sql.NullString `gorm:"column:password"`
	Host             string         `gorm:"column:host"`
	Port             string         `gorm:"column:port"`
	Directories      string         `gorm:"column:directories"`
	BootID           string         `gorm:"column:boot_id"`
	MountIDs         string         `gorm:"column:mount_ids"`
	CredentialID     string         `gorm:"column:credential_id"`
	CredentialFormat string         `gorm:"column:credential_format"`
	PasswordEnvelope []byte         `gorm:"column:password_envelope"`
	RowRevision      int64          `gorm:"column:row_revision"`
	PasswordType     string         `gorm:"column:password_type"`
	EnvelopeType     string         `gorm:"column:envelope_type"`
}

type cutoverTestSnapshot struct {
	Rows            []cutoverTestStoredRow
	Markers         []smbCredentialMarkerSnapshot
	Controls        []smbCredentialControlSnapshot
	ControlTableSQL string
}

func TestSMBCredentialCutoverAtomicallySealsLegacyRowsAndStopsPending(t *testing.T) {
	for _, journalMode := range []string{"DELETE", "WAL"} {
		t.Run(journalMode, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, journalMode)
			credentials := []cutoverTestCredential{
				{ID: 1, Username: "alice", Password: "cutover-password-sentinel-one", Host: "nas-one.internal", Port: "", Directories: "photos,backup$"},
				{ID: 2, Username: "bob", Password: "cutover-password-sentinel-two", Host: "nas-two.internal", Port: "445", Directories: "media"},
				{ID: 3, Username: "carol", Password: "", Host: "nas-three.internal", Port: "445", Directories: "empty-password"},
				{
					ID:          4,
					Username:    "dave",
					Password:    strings.Repeat("p", 1024),
					Host:        "nas-four.internal",
					Port:        "445",
					Directories: "maximum-password",
					BootID:      "11111111-2222-4333-8444-555555555555",
					MountIDs:    `{"maximum-password":123}`,
				},
			}
			insertCutoverTestCredentials(t, database, credentials)
			keyring := newCutoverTestKeyring(t)

			result, err := cutoverSMBCredentials(database, keyring)
			if err != nil {
				t.Fatalf("cutover failed: %v", err)
			}
			if !result.Migrated || !result.Pending || result.Rows != len(credentials) {
				t.Fatalf("cutover result = %+v", result)
			}

			storedRows := loadCutoverTestRows(t, database)
			if len(storedRows) != len(credentials) {
				t.Fatalf("stored rows = %d, want %d", len(storedRows), len(credentials))
			}
			for index := range storedRows {
				stored := storedRows[index]
				original := credentials[index]
				if stored.ID != original.ID || stored.Username != original.Username || stored.Host != original.Host || stored.Directories != original.Directories || stored.BootID != original.BootID || stored.MountIDs != original.MountIDs {
					t.Fatalf("non-credential fields changed for row %d", original.ID)
				}
				if stored.Password.Valid || stored.PasswordType != "null" || stored.EnvelopeType != "blob" || stored.CredentialFormat != smbcredentials.EnvelopeFormat || stored.RowRevision != 1 || stored.Port != "445" {
					t.Fatalf("row %d does not have canonical sealed storage", original.ID)
				}
				parsedID, parseErr := uuid.Parse(stored.CredentialID)
				if parseErr != nil || parsedID == uuid.Nil || parsedID.Version() != 4 || parsedID.String() != stored.CredentialID {
					t.Fatalf("row %d credential ID is not canonical UUIDv4", original.ID)
				}
				context := cutoverTestContext(stored)
				plaintext, openErr := keyring.Open(context, stored.PasswordEnvelope)
				if openErr != nil || string(plaintext) != original.Password {
					clear(plaintext)
					t.Fatalf("row %d envelope did not authenticate", original.ID)
				}
				clear(plaintext)
				keyID, keyIDErr := keyring.EnvelopeKeyID(context, stored.PasswordEnvelope)
				if keyIDErr != nil || keyID != keyring.ActiveID() {
					t.Fatalf("row %d envelope key is not the controlled active key", original.ID)
				}
				if original.Password != "" && bytes.Contains(stored.PasswordEnvelope, []byte(original.Password)) {
					t.Fatalf("row %d envelope contains plaintext", original.ID)
				}
			}

			assertCutoverPendingControl(t, database, keyring.ActiveID())
			if err := expandSMBCredentialSchema(database); err == nil {
				t.Fatal("legacy-only startup gate accepted pending sealed state")
			}

			before := snapshotCutoverDatabase(t, database)
			changesBefore := cutoverTotalChanges(t, database)
			second, err := cutoverSMBCredentials(database, keyring)
			if err != nil {
				t.Fatalf("pending reauthentication failed: %v", err)
			}
			if second.Migrated || !second.Pending || second.Rows != len(credentials) {
				t.Fatalf("pending reauthentication result = %+v", second)
			}
			after := snapshotCutoverDatabase(t, database)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("pending reauthentication changed durable state")
			}
			if changesAfter := cutoverTotalChanges(t, database); changesAfter != changesBefore {
				t.Fatalf("pending reauthentication total_changes=%d, want %d", changesAfter, changesBefore)
			}
		})
	}
}

func TestSMBCredentialCutoverBindsEmptyDatabaseToActiveKey(t *testing.T) {
	for _, journalMode := range []string{"DELETE", "WAL"} {
		t.Run(journalMode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "empty.db")
			database, handle := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, journalMode)
			keyring := newCutoverTestKeyring(t)
			result, err := cutoverSMBCredentials(database, keyring)
			if err != nil || !result.Migrated || !result.Pending || result.Rows != 0 {
				t.Fatalf("empty cutover result = %+v, err = %v", result, err)
			}
			assertCutoverPendingControl(t, database, keyring.ActiveID())
			controlBefore := cutoverControlFingerprint(t, database)
			closeSMBCredentialSchemaDatabase(t, handle)

			reopened, reopenedHandle := openSMBCredentialSchemaDatabaseAt(t, path)
			defer closeSMBCredentialSchemaDatabase(t, reopenedHandle)
			wrongKeyring := newCutoverTestKeyring(t)
			before := snapshotCutoverDatabase(t, reopened)
			if _, err := cutoverSMBCredentials(reopened, wrongKeyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("wrong key error = %v", err)
			}
			if after := snapshotCutoverDatabase(t, reopened); !reflect.DeepEqual(before, after) {
				t.Fatal("wrong key changed empty pending database")
			}
			rotated, err := keyring.Rotate()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(rotated.Destroy)
			if _, err := cutoverSMBCredentials(reopened, rotated); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("rotated empty-database key error = %v", err)
			}
			if after := snapshotCutoverDatabase(t, reopened); !reflect.DeepEqual(before, after) {
				t.Fatal("rotated key changed empty pending database")
			}
			if controlAfter := cutoverControlFingerprint(t, reopened); controlAfter != controlBefore {
				t.Fatalf("empty control changed: before=%q after=%q", controlBefore, controlAfter)
			}
		})
	}
}

func TestSMBCredentialCutoverPendingStateSurvivesCloseAndReopen(t *testing.T) {
	for _, journalMode := range []string{"DELETE", "WAL"} {
		t.Run(journalMode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reopen.db")
			database, handle := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, journalMode)
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{
				ID: 1, Username: "reopen-user", Password: "reopen-password-sentinel", Host: "nas.internal", Port: "445", Directories: "media",
			}})
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); err != nil {
				t.Fatal(err)
			}
			closeSMBCredentialSchemaDatabase(t, handle)

			reopened, reopenedHandle := openSMBCredentialSchemaDatabaseAt(t, path)
			defer closeSMBCredentialSchemaDatabase(t, reopenedHandle)
			changesBefore := cutoverTotalChanges(t, reopened)
			result, err := cutoverSMBCredentials(reopened, keyring)
			if err != nil || result.Migrated || !result.Pending || result.Rows != 1 {
				t.Fatalf("reopened pending result = %+v, err = %v", result, err)
			}
			if changesAfter := cutoverTotalChanges(t, reopened); changesAfter != changesBefore {
				t.Fatalf("reopened retry total_changes=%d, want %d", changesAfter, changesBefore)
			}
			assertCutoverPendingControl(t, reopened, keyring.ActiveID())
			if err := expandSMBCredentialSchema(reopened); err == nil {
				t.Fatal("legacy-only reopen accepted pending state")
			}
		})
	}
}

func TestSMBCredentialCutoverRejectsWrongAndRotatedActiveKeysWithoutWriting(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "WAL")
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{
		ID: 1, Username: "alice", Password: "wrong-key-password-sentinel", Host: "nas.internal", Port: "445", Directories: "media",
	}})
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); err != nil {
		t.Fatal(err)
	}
	before := snapshotCutoverDatabase(t, database)

	wrongKeyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, wrongKeyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("wrong key error = %v", err)
	}
	if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
		t.Fatal("wrong key changed pending state")
	}

	rotated, err := keyring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotated.Destroy)
	if rotated.ActiveID() == keyring.ActiveID() {
		t.Fatal("rotation did not change active key")
	}
	if _, err := cutoverSMBCredentials(database, rotated); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("rotated active key error = %v", err)
	}
	if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
		t.Fatal("rotated active key changed pending state")
	}
}

func TestSMBCredentialCutoverRejectsOldEnvelopeWhenControlMatchesRotatedActiveKey(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "WAL")
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{
		ID: 1, Username: "alice", Password: "old-envelope-sentinel", Host: "nas.internal", Port: "445", Directories: "media",
	}})
	oldKeyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, oldKeyring); err != nil {
		t.Fatal(err)
	}
	rotated, err := oldKeyring.Rotate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotated.Destroy)
	rotatedActiveID, err := decodeSMBCredentialActiveKeyID(rotated.ActiveID())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rotatedActiveID)
	if result := database.Exec("UPDATE o_smb_credential_key_control SET active_key_id = ? WHERE singleton = 1", rotatedActiveID); result.Error != nil || result.RowsAffected != 1 {
		t.Fatalf("arrange rotated control: error=%v rows=%d", result.Error, result.RowsAffected)
	}
	before := snapshotCutoverDatabase(t, database)
	if _, err := cutoverSMBCredentials(database, rotated); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("old envelope binding error = %v", err)
	}
	if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
		t.Fatal("old-envelope binding rejection changed pending state")
	}
}

func TestSMBCredentialCutoverRejectsAADAndEnvelopeTamperingWithoutWriting(t *testing.T) {
	for _, tamper := range []struct {
		name      string
		statement string
	}{
		{name: "host AAD", statement: "UPDATE o_connections SET host = 'other.internal' WHERE id = 1"},
		{name: "envelope", statement: "UPDATE o_connections SET password_envelope = zeroblob(length(password_envelope)) WHERE id = 1"},
	} {
		t.Run(tamper.name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{
				ID: 1, Username: "alice", Password: "tamper-password-sentinel", Host: "nas.internal", Port: "445", Directories: "media",
			}})
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(tamper.statement).Error; err != nil {
				t.Fatal(err)
			}
			before := snapshotCutoverDatabase(t, database)
			if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("tamper error = %v", err)
			}
			if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
				t.Fatal("failed tamper authentication changed durable state")
			}
		})
	}
}

func TestSMBCredentialCutoverRollsBackEveryRowMarkerAndControlOnLateFailure(t *testing.T) {
	for _, journalMode := range []string{"DELETE", "WAL"} {
		t.Run(journalMode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "late-rollback.db")
			database, handle := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, journalMode)
			credentials := []cutoverTestCredential{
				{ID: 1, Username: "alice", Password: "rollback-password-sentinel-one", Host: "one.internal", Port: "445", Directories: "one"},
				{ID: 2, Username: "bob", Password: "rollback-password-sentinel-two", Host: "two.internal", Port: "445", Directories: "two"},
			}
			insertCutoverTestCredentials(t, database, credentials)
			// The first row can take this partial unique value, while the second row
			// fails after the transaction has already sealed and updated row one.
			if err := database.Exec(`CREATE UNIQUE INDEX fail_second_smb_cutover
				ON o_connections(credential_format)
				WHERE credential_format IS NOT NULL`).Error; err != nil {
				t.Fatal(err)
			}
			keyring := newCutoverTestKeyring(t)
			_, err := cutoverSMBCredentials(database, keyring)
			if !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("late failure error = %v", err)
			}
			for _, forbidden := range []string{credentials[0].Password, credentials[1].Password} {
				if strings.Contains(err.Error(), forbidden) {
					t.Fatal("cutover error exposed private database content")
				}
			}
			assertLegacyCutoverRollback(t, database, credentials)
			assertCutoverWriterAvailable(t, database)
			closeSMBCredentialSchemaDatabase(t, handle)
			reopened, reopenedHandle := openSMBCredentialSchemaDatabaseAt(t, path)
			defer closeSMBCredentialSchemaDatabase(t, reopenedHandle)
			assertLegacyCutoverRollback(t, reopened, credentials)
			if err := reopened.Exec("DROP INDEX fail_second_smb_cutover").Error; err != nil {
				t.Fatal(err)
			}
			retry, retryErr := cutoverSMBCredentials(reopened, keyring)
			if retryErr != nil || !retry.Migrated || !retry.Pending || retry.Rows != len(credentials) {
				t.Fatalf("late-failure retry result=%+v err=%v", retry, retryErr)
			}
		})
	}
}

func TestSMBCredentialCutoverRollsBackUUIDCollisionAndEntropyFailure(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		generator func() func() (uuid.UUID, error)
	}{
		{
			name: "duplicate UUID",
			generator: func() func() (uuid.UUID, error) {
				fixed := uuid.MustParse("11111111-1111-4111-8111-111111111111")
				return func() (uuid.UUID, error) { return fixed, nil }
			},
		},
		{
			name: "second entropy failure",
			generator: func() func() (uuid.UUID, error) {
				calls := 0
				return func() (uuid.UUID, error) {
					calls++
					if calls == 2 {
						return uuid.Nil, errors.New("private entropy failure")
					}
					return uuid.MustParse("22222222-2222-4222-8222-222222222222"), nil
				}
			},
		},
	} {
		for _, journalMode := range []string{"DELETE", "WAL"} {
			t.Run(testCase.name+"/"+journalMode, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "injected-rollback.db")
				database, handle := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, journalMode)
				credentials := []cutoverTestCredential{
					{ID: 1, Username: "one", Password: "uuid-sentinel-one", Host: "one", Port: "445", Directories: "one"},
					{ID: 2, Username: "two", Password: "uuid-sentinel-two", Host: "two", Port: "445", Directories: "two"},
				}
				insertCutoverTestCredentials(t, database, credentials)
				keyring := newCutoverTestKeyring(t)
				dependencies := defaultSMBCredentialCutoverDependencies()
				dependencies.NewCredentialID = testCase.generator()
				_, err := cutoverSMBCredentialsWithDependencies(database, keyring, dependencies)
				if !errors.Is(err, errSMBCredentialCutover) {
					t.Fatalf("injected failure error = %v", err)
				}
				for _, forbidden := range []string{"private entropy failure", credentials[0].Password, credentials[1].Password} {
					if strings.Contains(err.Error(), forbidden) {
						t.Fatal("injected failure leaked private content")
					}
				}
				assertLegacyCutoverRollback(t, database, credentials)
				assertCutoverWriterAvailable(t, database)
				closeSMBCredentialSchemaDatabase(t, handle)
				reopened, reopenedHandle := openSMBCredentialSchemaDatabaseAt(t, path)
				defer closeSMBCredentialSchemaDatabase(t, reopenedHandle)
				assertLegacyCutoverRollback(t, reopened, credentials)
				retry, retryErr := cutoverSMBCredentials(reopened, keyring)
				if retryErr != nil || !retry.Migrated || !retry.Pending || retry.Rows != len(credentials) {
					t.Fatalf("injected-failure retry result=%+v err=%v", retry, retryErr)
				}
			})
		}
	}
}

func TestSMBCredentialCutoverRejectsIncompatibleStatesWithoutMutation(t *testing.T) {
	tests := map[string]func(*testing.T, *gorm.DB){
		"partial row": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "partial-sentinel", Host: "nas", Port: "445", Directories: "media"}})
			if err := database.Exec("UPDATE o_connections SET credential_id = ? WHERE id = 1", "11111111-1111-4111-8111-111111111111").Error; err != nil {
				t.Fatal(err)
			}
		},
		"pending plus legacy": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "pending-legacy-sentinel", Host: "nas", Port: "445", Directories: "media"}})
			if err := database.Exec("INSERT INTO o_security_migrations(name, state, updated) VALUES (?, ?, ?)", model2.SMBCredentialMigrationName, model2.SecurityMigrationPending, 1).Error; err != nil {
				t.Fatal(err)
			}
		},
		"invalid storage class": func(t *testing.T, database *gorm.DB) {
			if err := database.Exec("INSERT INTO o_connections(id, username, password, host, port, directories) VALUES (1, NULL, 'storage-sentinel', 'nas', '445', 'media')").Error; err != nil {
				t.Fatal(err)
			}
		},
		"connection trigger": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "trigger-sentinel", Host: "nas", Port: "445", Directories: "media"}})
			if err := database.Exec(`CREATE TRIGGER unsafe_cutover_trigger
				AFTER UPDATE OF password ON o_connections
				BEGIN SELECT 1; END`).Error; err != nil {
				t.Fatal(err)
			}
		},
		"temporary connection trigger": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "temp-trigger-sentinel", Host: "nas", Port: "445", Directories: "media"}})
			if err := database.Exec(`CREATE TEMP TRIGGER unsafe_temp_cutover_trigger
				AFTER UPDATE OF password ON main.o_connections
				BEGIN SELECT 1; END`).Error; err != nil {
				t.Fatal(err)
			}
		},
		"generated password shadow": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "generated-shadow-sentinel", Host: "nas", Port: "445", Directories: "media"}})
			if err := database.Exec(`ALTER TABLE o_connections
				ADD COLUMN password_shadow TEXT GENERATED ALWAYS AS (password) VIRTUAL`).Error; err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			arrange(t, database)
			before := snapshotCutoverDatabase(t, database)
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("incompatible state error = %v", err)
			}
			after := snapshotCutoverDatabase(t, database)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("incompatible state was mutated")
			}
			assertCutoverControlTableCount(t, database, 0)
		})
	}
}

func TestSMBCredentialCutoverRejectsRuntimeIncompatibleLegacyRowsWithoutWriting(t *testing.T) {
	tests := map[string]func(*testing.T, *gorm.DB){
		"username option injection": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "bad,user", Password: "secret", Host: "nas", Port: "445", Directories: "media"}})
		},
		"password option injection": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "bad\npassword", Host: "nas", Port: "445", Directories: "media"}})
		},
		"invalid host": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "secret", Host: "bad host", Port: "445", Directories: "media"}})
		},
		"noncanonical port": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "444", Directories: "media"}})
		},
		"unsafe directory": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "445", Directories: "../media"}})
		},
		"administrative shares only": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "445", Directories: "IPC$,ADMIN$"}})
		},
		"partial mount identity": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "445", Directories: "media", BootID: "boot-only"}})
		},
		"invalid mount identities": func(t *testing.T, database *gorm.DB) {
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "445", Directories: "media", BootID: "boot", MountIDs: "not-json"}})
		},
	}
	for name, arrange := range tests {
		t.Run(name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			arrange(t, database)
			before := snapshotCutoverDatabase(t, database)
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("runtime validation error = %v", err)
			}
			if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
				t.Fatal("runtime-incompatible legacy row was mutated")
			}
			assertCutoverControlTableCount(t, database, 0)
		})
	}
}

func TestSMBCredentialCutoverRejectsCaseVariantPasswordCaptureTriggers(t *testing.T) {
	for _, temporary := range []bool{false, true} {
		name := "main"
		if temporary {
			name = "temporary"
		}
		t.Run(name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "trigger-capture-sentinel", Host: "nas", Port: "445", Directories: "media"}})
			createTable := "CREATE TABLE smb_cutover_capture(secret TEXT)"
			createTrigger := `CREATE TRIGGER smb_cutover_capture_trigger
				AFTER UPDATE OF password ON O_CONNECTIONS
				BEGIN INSERT INTO smb_cutover_capture(secret) VALUES (OLD.password); END`
			captureTable := "main.smb_cutover_capture"
			if temporary {
				createTable = "CREATE TEMP TABLE smb_cutover_capture(secret TEXT)"
				createTrigger = `CREATE TEMP TRIGGER smb_cutover_capture_trigger
					AFTER UPDATE OF password ON main.O_CONNECTIONS
					BEGIN INSERT INTO smb_cutover_capture(secret) VALUES (OLD.password); END`
				captureTable = "temp.smb_cutover_capture"
			}
			if err := database.Exec(createTable).Error; err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(createTrigger).Error; err != nil {
				t.Fatal(err)
			}
			before := snapshotCutoverDatabase(t, database)
			changesBefore := cutoverTotalChanges(t, database)
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("case-variant trigger error = %v", err)
			}
			if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
				t.Fatal("trigger rejection changed credential state")
			}
			if changesAfter := cutoverTotalChanges(t, database); changesAfter != changesBefore {
				t.Fatalf("trigger rejection total_changes=%d, want %d", changesAfter, changesBefore)
			}
			var captured int64
			if err := database.Raw("SELECT count(*) FROM " + captureTable).Scan(&captured).Error; err != nil || captured != 0 {
				t.Fatalf("captured rows=%d err=%v", captured, err)
			}
			assertCutoverControlTableCount(t, database, 0)
		})
	}
}

func TestSMBCredentialCutoverRejectsInboundForeignKeyCascade(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	if err := database.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		t.Fatal(err)
	}
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "foreign-key-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	if err := database.Exec("CREATE UNIQUE INDEX ux_cutover_password_reference ON o_connections(password)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec(`CREATE TABLE smb_cutover_child (
		secret_copy TEXT REFERENCES O_CONNECTIONS(password) ON UPDATE CASCADE
	)`).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("INSERT INTO smb_cutover_child(secret_copy) VALUES (?)", "foreign-key-sentinel").Error; err != nil {
		t.Fatal(err)
	}
	before := snapshotCutoverDatabase(t, database)
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("inbound foreign key error = %v", err)
	}
	if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
		t.Fatal("foreign-key rejection changed credential state")
	}
	var childSecret string
	if err := database.Raw("SELECT secret_copy FROM smb_cutover_child").Scan(&childSecret).Error; err != nil || childSecret != "foreign-key-sentinel" {
		t.Fatalf("child secret=%q err=%v", childSecret, err)
	}
	assertCutoverControlTableCount(t, database, 0)
}

func TestSMBCredentialCutoverAllowsUnrelatedTriggersAndForeignKeys(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	if err := database.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("CREATE TABLE unrelated_parent(id INTEGER PRIMARY KEY)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("CREATE TABLE unrelated_child(parent_id INTEGER REFERENCES unrelated_parent(id))").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec("CREATE TABLE unrelated_audit(value INTEGER)").Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Exec(`CREATE TRIGGER unrelated_trigger AFTER INSERT ON unrelated_parent
		BEGIN INSERT INTO unrelated_audit(value) VALUES (NEW.id); END`).Error; err != nil {
		t.Fatal(err)
	}
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "unrelated-schema-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	keyring := newCutoverTestKeyring(t)
	result, err := cutoverSMBCredentials(database, keyring)
	if err != nil || !result.Migrated || !result.Pending || result.Rows != 1 {
		t.Fatalf("unrelated schema result=%+v err=%v", result, err)
	}
	assertCutoverPendingControl(t, database, keyring.ActiveID())
}

func TestSMBCredentialCutoverRejectsNullPortButNormalizesEmptyTextPort(t *testing.T) {
	t.Run("NULL is invalid storage", func(t *testing.T) {
		database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
		insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "null-port-sentinel", Host: "nas", Port: "445", Directories: "media"}})
		if err := database.Exec("UPDATE o_connections SET port = NULL WHERE id = 1").Error; err != nil {
			t.Fatal(err)
		}
		keyring := newCutoverTestKeyring(t)
		if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
			t.Fatalf("NULL port error = %v", err)
		}
		var portType string
		if err := database.Raw("SELECT typeof(port) FROM o_connections WHERE id = 1").Scan(&portType).Error; err != nil || portType != "null" {
			t.Fatalf("NULL port changed: type=%q err=%v", portType, err)
		}
		assertCutoverMarkerCount(t, database, 0)
		assertCutoverControlTableCount(t, database, 0)
	})

	t.Run("empty TEXT becomes 445", func(t *testing.T) {
		database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
		insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "empty-port-sentinel", Host: "nas", Port: "", Directories: "media"}})
		keyring := newCutoverTestKeyring(t)
		result, err := cutoverSMBCredentials(database, keyring)
		if err != nil || !result.Migrated || result.Rows != 1 {
			t.Fatalf("empty port result=%+v err=%v", result, err)
		}
		rows := loadCutoverTestRows(t, database)
		if len(rows) != 1 || rows[0].Port != "445" {
			t.Fatalf("normalized port row=%+v", rows)
		}
	})
}

func TestSMBCredentialCutoverPreflightsOversizedValuesBeforeWriting(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		credential cutoverTestCredential
	}{
		{
			name:       "password",
			credential: cutoverTestCredential{ID: 1, Username: "user", Password: strings.Repeat("p", maxSMBCredentialPasswordBytes+1), Host: "nas", Port: "445", Directories: "media"},
		},
		{
			name:       "directories",
			credential: cutoverTestCredential{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "445", Directories: strings.Repeat("d", maxSMBCredentialDirectoriesBytes+1)},
		},
		{
			name:       "mount IDs",
			credential: cutoverTestCredential{ID: 1, Username: "user", Password: "secret", Host: "nas", Port: "445", Directories: "media", BootID: "boot", MountIDs: strings.Repeat("m", maxSMBCredentialMountIDsBytes+1)},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			insertCutoverTestCredentials(t, database, []cutoverTestCredential{testCase.credential})
			keyring := newCutoverTestKeyring(t)
			generatorCalls := 0
			dependencies := defaultSMBCredentialCutoverDependencies()
			dependencies.NewCredentialID = func() (uuid.UUID, error) {
				generatorCalls++
				return uuid.NewRandom()
			}
			changesBefore := cutoverTotalChanges(t, database)
			if _, err := cutoverSMBCredentialsWithDependencies(database, keyring, dependencies); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("oversized %s error = %v", testCase.name, err)
			}
			if generatorCalls != 0 {
				t.Fatalf("oversized preflight generated %d credential IDs", generatorCalls)
			}
			if changesAfter := cutoverTotalChanges(t, database); changesAfter != changesBefore {
				t.Fatalf("oversized preflight total_changes=%d, want %d", changesAfter, changesBefore)
			}
			assertCutoverMarkerCount(t, database, 0)
			assertCutoverControlTableCount(t, database, 0)
			var passwordType string
			if err := database.Raw("SELECT typeof(password) FROM o_connections WHERE id = 1").Scan(&passwordType).Error; err != nil || passwordType != "text" {
				t.Fatalf("oversized row changed: type=%q err=%v", passwordType, err)
			}
		})
	}
}

func TestSMBCredentialCutoverRejectsCompleteStateBecauseScrubCoordinatorOwnsCompletion(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "complete-state-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); err != nil {
		t.Fatal(err)
	}
	if result := database.Exec("UPDATE o_security_migrations SET state = ? WHERE name = ?", model2.SecurityMigrationComplete, model2.SMBCredentialMigrationName); result.Error != nil || result.RowsAffected != 1 {
		t.Fatalf("arrange complete marker: error=%v rows=%d", result.Error, result.RowsAffected)
	}
	before := snapshotCutoverDatabase(t, database)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("complete state error = %v", err)
	}
	if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
		t.Fatal("transaction core changed complete state")
	}
}

func TestSMBCredentialCutoverRejectsConflictingControlSchemaAndPreservesIt(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	if err := database.Exec(`CREATE TABLE o_smb_credential_key_control (
		singleton INTEGER PRIMARY KEY,
		active_key_id TEXT,
		revision INTEGER
	)`).Error; err != nil {
		t.Fatal(err)
	}
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "schema-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	before := snapshotCutoverDatabase(t, database)
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("conflicting control error = %v", err)
	}
	if after := snapshotCutoverDatabase(t, database); !reflect.DeepEqual(before, after) {
		t.Fatal("conflicting control schema was changed")
	}
}

func TestSMBCredentialCutoverRejectsMalformedBaseSchemaEvenWhenEmpty(t *testing.T) {
	for _, testCase := range []struct {
		name               string
		idDefinition       string
		usernameDefinition string
		passwordDefinition string
	}{
		{name: "noninteger primary key", idDefinition: "TEXT PRIMARY KEY", usernameDefinition: "TEXT", passwordDefinition: "TEXT"},
		{name: "non-rowid primary key", idDefinition: "INTEGER PRIMARY KEY DESC", usernameDefinition: "TEXT", passwordDefinition: "TEXT"},
		{name: "missing primary key", idDefinition: "INTEGER", usernameDefinition: "TEXT", passwordDefinition: "TEXT"},
		{name: "username type", idDefinition: "INTEGER PRIMARY KEY", usernameDefinition: "BLOB", passwordDefinition: "TEXT"},
		{name: "password default", idDefinition: "INTEGER PRIMARY KEY", usernameDefinition: "TEXT", passwordDefinition: "TEXT DEFAULT ''"},
		{name: "virtual generated password", idDefinition: "INTEGER PRIMARY KEY", usernameDefinition: "TEXT", passwordDefinition: "TEXT GENERATED ALWAYS AS (username) VIRTUAL"},
		{name: "stored generated password", idDefinition: "INTEGER PRIMARY KEY", usernameDefinition: "TEXT", passwordDefinition: "TEXT GENERATED ALWAYS AS (username) STORED"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			if err := database.Exec("DROP TABLE o_connections").Error; err != nil {
				t.Fatal(err)
			}
			statement := fmt.Sprintf(`CREATE TABLE o_connections (
				id %s,
				updated INTEGER,
				created INTEGER,
				username %s,
				password %s,
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
			)`, testCase.idDefinition, testCase.usernameDefinition, testCase.passwordDefinition)
			if err := database.Exec(statement).Error; err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(createCredentialIDIndexSQL).Error; err != nil {
				t.Fatal(err)
			}
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("malformed base schema error = %v", err)
			}
			assertCutoverMarkerCount(t, database, 0)
			assertCutoverControlTableCount(t, database, 0)
		})
	}
}

func TestSMBCredentialCutoverRejectsEveryMalformedControlRowWithoutWriting(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		statement string
	}{
		{name: "TEXT key ID", statement: "UPDATE o_smb_credential_key_control SET active_key_id = CAST(active_key_id AS TEXT)"},
		{name: "31-byte key ID", statement: "UPDATE o_smb_credential_key_control SET active_key_id = zeroblob(31)"},
		{name: "33-byte key ID", statement: "UPDATE o_smb_credential_key_control SET active_key_id = zeroblob(33)"},
		{name: "wrong 32-byte key ID", statement: "UPDATE o_smb_credential_key_control SET active_key_id = zeroblob(32)"},
		{name: "revision two", statement: "UPDATE o_smb_credential_key_control SET revision = 2"},
		{name: "BLOB revision", statement: "UPDATE o_smb_credential_key_control SET revision = CAST(X'31' AS BLOB)"},
		{name: "wrong singleton", statement: "UPDATE o_smb_credential_key_control SET singleton = 2"},
		{name: "extra row", statement: "INSERT INTO o_smb_credential_key_control(singleton, active_key_id, revision) VALUES (2, zeroblob(32), 1)"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
			keyring := newCutoverTestKeyring(t)
			if _, err := cutoverSMBCredentials(database, keyring); err != nil {
				t.Fatal(err)
			}
			if err := database.Exec("PRAGMA ignore_check_constraints = ON").Error; err != nil {
				t.Fatal(err)
			}
			if err := database.Exec(testCase.statement).Error; err != nil {
				t.Fatal(err)
			}
			before := cutoverControlFingerprint(t, database)
			if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
				t.Fatalf("malformed control error = %v", err)
			}
			after := cutoverControlFingerprint(t, database)
			if before != after {
				t.Fatalf("malformed control changed: before=%q after=%q", before, after)
			}
			assertCutoverMarkerCount(t, database, 1)
		})
	}
}

func TestSMBCredentialCutoverPreflightsMarkerAndControlRowsBeforeMaterializingValues(t *testing.T) {
	const oversizedBytes = 1 << 20

	t.Run("oversized marker name", func(t *testing.T) {
		database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
		if err := database.Exec(`INSERT INTO o_security_migrations(name, state, updated)
			VALUES (replace(hex(zeroblob(?)), '00', 'm'), ?, 1)`, oversizedBytes, model2.SecurityMigrationPending).Error; err != nil {
			t.Fatal(err)
		}
		mainSchemaBefore := cutoverSchemaFingerprint(t, database, "main")
		mainVersionBefore := cutoverSchemaVersion(t, database, "main")
		changesBefore := cutoverTotalChanges(t, database)
		keyring := newCutoverTestKeyring(t)
		if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
			t.Fatalf("oversized marker error = %v", err)
		}
		if changesAfter := cutoverTotalChanges(t, database); changesAfter != changesBefore {
			t.Fatalf("oversized marker total_changes=%d, want %d", changesAfter, changesBefore)
		}
		if after := cutoverSchemaFingerprint(t, database, "main"); after != mainSchemaBefore {
			t.Fatal("oversized marker changed main schema")
		}
		if after := cutoverSchemaVersion(t, database, "main"); after != mainVersionBefore {
			t.Fatalf("oversized marker schema_version=%d, want %d", after, mainVersionBefore)
		}
		var rowCount, nameBytes int64
		if err := database.Raw("SELECT count(*), max(length(CAST(name AS BLOB))) FROM main.o_security_migrations").Row().Scan(&rowCount, &nameBytes); err != nil {
			t.Fatal(err)
		}
		if rowCount != 1 || nameBytes != oversizedBytes {
			t.Fatalf("oversized marker changed: rows=%d bytes=%d", rowCount, nameBytes)
		}
		assertCutoverControlTableCount(t, database, 0)
	})

	t.Run("oversized control key", func(t *testing.T) {
		database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
		if err := database.Exec(createSMBCredentialControlTableSQL).Error; err != nil {
			t.Fatal(err)
		}
		if err := database.Exec("PRAGMA ignore_check_constraints = ON").Error; err != nil {
			t.Fatal(err)
		}
		if err := database.Exec(`INSERT INTO o_smb_credential_key_control(singleton, active_key_id, revision)
			VALUES (1, zeroblob(?), 1)`, oversizedBytes).Error; err != nil {
			t.Fatal(err)
		}
		mainSchemaBefore := cutoverSchemaFingerprint(t, database, "main")
		mainVersionBefore := cutoverSchemaVersion(t, database, "main")
		changesBefore := cutoverTotalChanges(t, database)
		keyring := newCutoverTestKeyring(t)
		if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
			t.Fatalf("oversized control error = %v", err)
		}
		if changesAfter := cutoverTotalChanges(t, database); changesAfter != changesBefore {
			t.Fatalf("oversized control total_changes=%d, want %d", changesAfter, changesBefore)
		}
		if after := cutoverSchemaFingerprint(t, database, "main"); after != mainSchemaBefore {
			t.Fatal("oversized control changed main schema")
		}
		if after := cutoverSchemaVersion(t, database, "main"); after != mainVersionBefore {
			t.Fatalf("oversized control schema_version=%d, want %d", after, mainVersionBefore)
		}
		var rowCount, keyBytes int64
		if err := database.Raw("SELECT count(*), max(length(active_key_id)) FROM main.o_smb_credential_key_control").Row().Scan(&rowCount, &keyBytes); err != nil {
			t.Fatal(err)
		}
		if rowCount != 1 || keyBytes != oversizedBytes {
			t.Fatalf("oversized control changed: rows=%d bytes=%d", rowCount, keyBytes)
		}
		assertCutoverMarkerCount(t, database, 0)
	})
}

func TestSMBCredentialCutoverEnforcesRowBoundBeforeWriting(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	statement := fmt.Sprintf(`WITH RECURSIVE sequence(value) AS (
		VALUES(1)
		UNION ALL SELECT value + 1 FROM sequence WHERE value < %d
	)
	INSERT INTO o_connections(id, username, password, host, port, directories)
	SELECT value, 'user', 'bounded-password', 'nas', '445', 'media' FROM sequence`, maxSMBCredentialRows+1)
	if err := database.Exec(statement).Error; err != nil {
		t.Fatal(err)
	}
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("row bound error = %v", err)
	}
	assertCutoverMarkerCount(t, database, 0)
	assertCutoverControlTableCount(t, database, 0)
	var count int64
	if err := database.Raw("SELECT count(*) FROM o_connections WHERE password = 'bounded-password'").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != maxSMBCredentialRows+1 {
		t.Fatalf("row-bound failure changed %d rows", maxSMBCredentialRows+1-count)
	}
}

func TestSMBCredentialCutoverUsesImmediateWriterAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "busy.db")
	databaseA, handleA := openSMBCredentialSchemaDatabaseAt(t, path)
	defer closeSMBCredentialSchemaDatabase(t, handleA)
	if err := expandSMBCredentialSchema(databaseA); err != nil {
		t.Fatal(err)
	}
	insertCutoverTestCredentials(t, databaseA, []cutoverTestCredential{{ID: 1, Username: "user", Password: "busy-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	databaseB, handleB := openSMBCredentialSchemaDatabaseAt(t, path)
	defer closeSMBCredentialSchemaDatabase(t, handleB)
	if err := databaseB.Exec("PRAGMA busy_timeout = 0").Error; err != nil {
		t.Fatal(err)
	}
	if err := databaseA.Exec("BEGIN IMMEDIATE").Error; err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_ = databaseA.Exec("ROLLBACK").Error
		}
	}()
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(databaseB, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("writer admission error = %v", err)
	}
	if err := databaseA.Exec("ROLLBACK").Error; err != nil {
		t.Fatal(err)
	}
	locked = false
	assertCutoverMarkerCount(t, databaseA, 0)
	assertCutoverControlTableCount(t, databaseA, 0)
}

func TestSMBCredentialImmediateTransactionAcquiresWriterLockBeforeCallback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "immediate-callback.db")
	databaseA, handleA := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, "WAL")
	defer closeSMBCredentialSchemaDatabase(t, handleA)
	databaseB, handleB := openSMBCredentialSchemaDatabaseAt(t, path)
	defer closeSMBCredentialSchemaDatabase(t, handleB)
	if err := databaseB.Exec("PRAGMA busy_timeout = 0").Error; err != nil {
		t.Fatal(err)
	}

	callbackStarted := make(chan struct{})
	releaseCallback := make(chan struct{})
	transactionResult := make(chan error, 1)
	go func() {
		transactionResult <- withImmediateSMBCredentialTransaction(databaseA, func(*gorm.DB) error {
			close(callbackStarted)
			<-releaseCallback
			return errors.New("intentional callback rollback")
		})
	}()
	<-callbackStarted
	secondWriterErr := databaseB.Exec("BEGIN IMMEDIATE").Error
	close(releaseCallback)
	firstWriterErr := <-transactionResult
	if secondWriterErr == nil {
		_ = databaseB.Exec("ROLLBACK").Error
		t.Fatal("second writer entered while the callback was running")
	}
	if firstWriterErr == nil {
		t.Fatal("intentional callback failure was lost")
	}
	if err := databaseB.Exec("BEGIN IMMEDIATE").Error; err != nil {
		t.Fatalf("writer lock remained after rollback: %v", err)
	}
	if err := databaseB.Exec("ROLLBACK").Error; err != nil {
		t.Fatal(err)
	}
}

func TestSMBCredentialImmediateTransactionRollsBackAfterCallerContextCancellation(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "WAL")
	if err := database.Exec("CREATE TABLE rollback_probe(value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	operationContext, cancelOperation := context.WithCancel(context.Background())
	err := withImmediateSMBCredentialTransaction(database.WithContext(operationContext), func(transaction *gorm.DB) error {
		if insertErr := transaction.Exec("INSERT INTO rollback_probe(value) VALUES ('must-rollback')").Error; insertErr != nil {
			return insertErr
		}
		cancelOperation()
		return errors.New("intentional cancellation")
	})
	if err == nil {
		t.Fatal("canceled operation unexpectedly committed")
	}
	var rows int64
	if queryErr := database.Raw("SELECT count(*) FROM rollback_probe").Scan(&rows).Error; queryErr != nil || rows != 0 {
		t.Fatalf("canceled operation rows=%d err=%v", rows, queryErr)
	}
	if beginErr := database.Exec("BEGIN IMMEDIATE").Error; beginErr != nil {
		t.Fatalf("canceled operation left writer lock: %v", beginErr)
	}
	if rollbackErr := database.Exec("ROLLBACK").Error; rollbackErr != nil {
		t.Fatal(rollbackErr)
	}
}

func TestSMBCredentialImmediateTransactionDiscardsConnectionWhenRollbackOutcomeIsUnknown(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	if err := database.Exec("CREATE TABLE durable_probe(value TEXT)").Error; err != nil {
		t.Fatal(err)
	}
	err := withImmediateSMBCredentialTransaction(database, func(transaction *gorm.DB) error {
		if createErr := transaction.Exec("CREATE TEMP TABLE poisoned_connection(value TEXT)").Error; createErr != nil {
			return createErr
		}
		sqlConnection, operationContext, connectionErr := smbCredentialSQLConnection(transaction)
		if connectionErr != nil {
			return connectionErr
		}
		if _, insertErr := sqlConnection.ExecContext(operationContext, "INSERT INTO durable_probe(value) VALUES ('committed-before-error')"); insertErr != nil {
			return insertErr
		}
		if _, commitErr := sqlConnection.ExecContext(operationContext, "COMMIT"); commitErr != nil {
			return commitErr
		}
		return errors.New("private error after manual commit")
	})
	if !errors.Is(err, errSMBCredentialCutover) || strings.Contains(err.Error(), "private error") {
		t.Fatalf("unknown rollback error = %v", err)
	}
	var durableRows int64
	if queryErr := database.Raw("SELECT count(*) FROM durable_probe").Scan(&durableRows).Error; queryErr != nil || durableRows != 1 {
		t.Fatalf("durable rows=%d err=%v", durableRows, queryErr)
	}
	if queryErr := database.Raw("SELECT count(*) FROM temp.poisoned_connection").Scan(new(int64)).Error; queryErr == nil {
		t.Fatal("poisoned physical connection was returned to the pool")
	}
}

func TestSMBCredentialCutoverConcurrentMigratorsConvergeOnOnePendingState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "concurrent-cutover.db")
	databaseA, handleA := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, "WAL")
	defer closeSMBCredentialSchemaDatabase(t, handleA)
	insertCutoverTestCredentials(t, databaseA, []cutoverTestCredential{{ID: 1, Username: "user", Password: "concurrent-cutover-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	databaseB, handleB := openSMBCredentialSchemaDatabaseAt(t, path)
	defer closeSMBCredentialSchemaDatabase(t, handleB)
	for _, database := range []*gorm.DB{databaseA, databaseB} {
		if err := database.Exec("PRAGMA busy_timeout = 5000").Error; err != nil {
			t.Fatal(err)
		}
	}
	keyring := newCutoverTestKeyring(t)
	type concurrentResult struct {
		result smbCredentialCutoverResult
		err    error
	}
	start := make(chan struct{})
	results := make(chan concurrentResult, 2)
	for _, database := range []*gorm.DB{databaseA, databaseB} {
		go func(candidate *gorm.DB) {
			<-start
			result, err := cutoverSMBCredentials(candidate, keyring)
			results <- concurrentResult{result: result, err: err}
		}(database)
	}
	close(start)
	first := <-results
	second := <-results
	migrations := 0
	for index, candidate := range []concurrentResult{first, second} {
		if candidate.err != nil || !candidate.result.Pending || candidate.result.Rows != 1 {
			t.Fatalf("concurrent result %d=%+v err=%v", index, candidate.result, candidate.err)
		}
		if candidate.result.Migrated {
			migrations++
		}
	}
	if migrations != 1 {
		t.Fatalf("successful migrations=%d, want 1", migrations)
	}
	assertCutoverPendingControl(t, databaseA, keyring.ActiveID())
}

func TestSMBCredentialCutoverRejectsTemporarySchemaShadows(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "temp-shadow-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	if err := database.Exec("CREATE TEMP TABLE o_connections(id INTEGER PRIMARY KEY)").Error; err != nil {
		t.Fatal(err)
	}
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("temporary shadow error = %v", err)
	}
	if err := database.Exec("DROP TABLE temp.o_connections").Error; err != nil {
		t.Fatal(err)
	}
	assertCutoverMarkerCount(t, database, 0)
	assertCutoverControlTableCount(t, database, 0)
	stored := loadCutoverTestRows(t, database)
	if len(stored) != 1 || !stored[0].Password.Valid || stored[0].Password.String != "temp-shadow-sentinel" {
		t.Fatal("temporary shadow failure changed main credential row")
	}
}

func TestSMBCredentialCutoverRejectsAttachedDatabasesWithoutWriting(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "attached-database-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	attachedPath := filepath.Join(t.TempDir(), "attached.db")
	if err := database.Exec("ATTACH DATABASE ? AS auxiliary", attachedPath).Error; err != nil {
		t.Fatal(err)
	}
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("attached database error = %v", err)
	}
	if err := database.Exec("DETACH DATABASE auxiliary").Error; err != nil {
		t.Fatal(err)
	}
	stored := loadCutoverTestRows(t, database)
	if len(stored) != 1 || !stored[0].Password.Valid || stored[0].Password.String != "attached-database-sentinel" {
		t.Fatal("attached database rejection changed credential state")
	}
	assertCutoverMarkerCount(t, database, 0)
	assertCutoverControlTableCount(t, database, 0)
}

func TestSMBCredentialCutoverRejectsUnsupportedJournalMode(t *testing.T) {
	database := openSMBCredentialSchemaTestDatabase(t)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := database.Raw("PRAGMA journal_mode = OFF").Scan(&mode).Error; err != nil || !strings.EqualFold(mode, "off") {
		t.Fatalf("arrange journal mode = %q, err = %v", mode, err)
	}
	insertCutoverTestCredentials(t, database, []cutoverTestCredential{{ID: 1, Username: "user", Password: "journal-mode-sentinel", Host: "nas", Port: "445", Directories: "media"}})
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(database, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("unsupported journal error = %v", err)
	}
	assertCutoverMarkerCount(t, database, 0)
	assertCutoverControlTableCount(t, database, 0)
}

func TestSMBCredentialCutoverRejectsNilAndDestroyedDependencies(t *testing.T) {
	database := newSMBCredentialCutoverTestDatabase(t, "DELETE")
	keyring := newCutoverTestKeyring(t)
	if _, err := cutoverSMBCredentials(nil, keyring); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("nil database error = %v", err)
	}
	if _, err := cutoverSMBCredentials(database, nil); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("nil keyring error = %v", err)
	}
	destroyed, err := smbcredentials.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	destroyed.Destroy()
	if _, err := cutoverSMBCredentials(database, destroyed); !errors.Is(err, errSMBCredentialCutover) {
		t.Fatalf("destroyed keyring error = %v", err)
	}
	assertCutoverControlTableCount(t, database, 0)
}

func TestSMBCredentialCutoverNeverEmitsCredentialsToParentInfoLogger(t *testing.T) {
	for _, lateFailure := range []bool{false, true} {
		name := "success"
		if lateFailure {
			name = "rollback"
		}
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			diagnosticLogger := gormlogger.New(
				log.New(&output, "", 0),
				gormlogger.Config{LogLevel: gormlogger.Info, ParameterizedQueries: false, Colorful: false},
			)
			path := filepath.Join(t.TempDir(), "logger.db")
			database, err := gorm.Open(glebarezsqlite.Open(path), &gorm.Config{Logger: diagnosticLogger})
			if err != nil {
				t.Fatal(err)
			}
			handle, err := database.DB()
			if err != nil {
				t.Fatal(err)
			}
			handle.SetMaxOpenConns(1)
			defer closeSMBCredentialSchemaDatabase(t, handle)
			if err := expandSMBCredentialSchema(database); err != nil {
				t.Fatal(err)
			}
			credentials := []cutoverTestCredential{{ID: 1, Username: "logger-user-one", Password: "logger-secret-sentinel-one", Host: "logger-one.internal", Port: "445", Directories: "private-one"}}
			if lateFailure {
				credentials = append(credentials, cutoverTestCredential{ID: 2, Username: "logger-user-two", Password: "logger-secret-sentinel-two", Host: "logger-two.internal", Port: "445", Directories: "private-two"})
			}
			insertCutoverTestCredentials(t, database, credentials)
			if lateFailure {
				if err := database.Exec(`CREATE UNIQUE INDEX fail_logged_cutover
					ON o_connections(credential_format)
					WHERE credential_format IS NOT NULL`).Error; err != nil {
					t.Fatal(err)
				}
			}
			output.Reset()
			keyring := newCutoverTestKeyring(t)
			_, cutoverErr := cutoverSMBCredentials(database, keyring)
			if lateFailure && !errors.Is(cutoverErr, errSMBCredentialCutover) {
				t.Fatalf("logged rollback error = %v", cutoverErr)
			}
			if !lateFailure && cutoverErr != nil {
				t.Fatal(cutoverErr)
			}
			logged := output.String()
			for _, credential := range credentials {
				for _, privateValue := range []string{credential.Username, credential.Password, credential.Host, credential.Directories} {
					if strings.Contains(logged, privateValue) {
						t.Fatalf("parent logger exposed private value %q", privateValue)
					}
				}
			}
		})
	}
}

func TestSMBCredentialCutoverHasNoProductionCallSite(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate cutover test source")
	}
	directory := filepath.Dir(currentFile)
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	fileset := token.NewFileSet()
	targets := map[string]struct{}{
		"cutoverSMBCredentials":                 {},
		"cutoverSMBCredentialsWithDependencies": {},
	}
	declarations := make(map[string]int, len(targets))
	allowedWrapperCalls := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		parsed, parseErr := parser.ParseFile(fileset, path, nil, 0)
		if parseErr != nil {
			t.Fatal(parseErr)
		}
		allowed := make(map[token.Pos]struct{})
		for _, declaration := range parsed.Decls {
			function, isFunction := declaration.(*ast.FuncDecl)
			if !isFunction {
				continue
			}
			if _, target := targets[function.Name.Name]; target {
				allowed[function.Name.Pos()] = struct{}{}
				declarations[function.Name.Name]++
			}
			if function.Name.Name != "cutoverSMBCredentials" || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, isCall := node.(*ast.CallExpr)
				if !isCall {
					return true
				}
				identifier, isIdentifier := call.Fun.(*ast.Ident)
				if isIdentifier && identifier.Name == "cutoverSMBCredentialsWithDependencies" {
					allowed[identifier.Pos()] = struct{}{}
					allowedWrapperCalls++
				}
				return true
			})
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			identifier, isIdentifier := node.(*ast.Ident)
			if !isIdentifier {
				return true
			}
			if _, target := targets[identifier.Name]; !target {
				return true
			}
			if _, permitted := allowed[identifier.Pos()]; !permitted {
				t.Errorf("production reference to %s at %s", identifier.Name, fileset.Position(identifier.Pos()))
			}
			return true
		})
	}
	for target := range targets {
		if declarations[target] != 1 {
			t.Errorf("production declarations for %s = %d, want 1", target, declarations[target])
		}
	}
	if allowedWrapperCalls != 1 {
		t.Errorf("wrapper calls to cutoverSMBCredentialsWithDependencies = %d, want 1", allowedWrapperCalls)
	}
}

func newSMBCredentialCutoverTestDatabase(t *testing.T, journalMode string) *gorm.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "cutover.db")
	database, handle := openExpandedSMBCredentialCutoverTestDatabaseAt(t, path, journalMode)
	t.Cleanup(func() { closeSMBCredentialSchemaDatabase(t, handle) })
	return database
}

func openExpandedSMBCredentialCutoverTestDatabaseAt(t *testing.T, path, journalMode string) (*gorm.DB, *sql.DB) {
	t.Helper()
	database, handle := openSMBCredentialSchemaDatabaseAt(t, path)
	if err := expandSMBCredentialSchema(database); err != nil {
		t.Fatal(err)
	}
	var actualMode string
	if err := database.Raw("PRAGMA journal_mode = " + journalMode).Scan(&actualMode).Error; err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(actualMode, journalMode) {
		t.Fatalf("journal mode = %q, want %q", actualMode, journalMode)
	}
	return database, handle
}

func newCutoverTestKeyring(t *testing.T) *smbcredentials.Keyring {
	t.Helper()
	keyring, err := smbcredentials.NewKeyring()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(keyring.Destroy)
	return keyring
}

func insertCutoverTestCredentials(t *testing.T, database *gorm.DB, credentials []cutoverTestCredential) {
	t.Helper()
	for _, credential := range credentials {
		if err := database.Exec(`INSERT INTO o_connections(
			id, username, password, host, port, status, directories, mount_point, boot_id, mount_ids
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			credential.ID,
			credential.Username,
			credential.Password,
			credential.Host,
			credential.Port,
			"ready",
			credential.Directories,
			"/mnt/"+credential.Host,
			credential.BootID,
			credential.MountIDs,
		).Error; err != nil {
			t.Fatal(err)
		}
	}
}

func loadCutoverTestRows(t *testing.T, database *gorm.DB) []cutoverTestStoredRow {
	t.Helper()
	var rows []cutoverTestStoredRow
	if err := database.Raw(`SELECT
			id, username, password, host, port, directories, boot_id, mount_ids,
		coalesce(credential_id, '') AS credential_id,
		coalesce(credential_format, '') AS credential_format,
		coalesce(password_envelope, zeroblob(0)) AS password_envelope,
		row_revision,
		typeof(password) AS password_type,
		typeof(password_envelope) AS envelope_type
		FROM o_connections ORDER BY id`).Scan(&rows).Error; err != nil {
		t.Fatal(err)
	}
	return rows
}

func cutoverTestContext(row cutoverTestStoredRow) smbcredentials.Context {
	return smbcredentials.Context{
		CredentialID: row.CredentialID,
		Username:     row.Username,
		Host:         row.Host,
		Port:         row.Port,
		Directories:  row.Directories,
	}
}

func snapshotCutoverDatabase(t *testing.T, database *gorm.DB) cutoverTestSnapshot {
	t.Helper()
	snapshot := cutoverTestSnapshot{Rows: loadCutoverTestRows(t, database)}
	if err := database.Raw(`SELECT
		name, state, updated,
		typeof(name) AS name_type,
		typeof(state) AS state_type,
		typeof(updated) AS updated_type
		FROM o_security_migrations ORDER BY name`).Scan(&snapshot.Markers).Error; err != nil {
		t.Fatal(err)
	}
	var controlTableCount int64
	if err := database.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", smbCredentialControlTableName).Scan(&controlTableCount).Error; err != nil {
		t.Fatal(err)
	}
	if controlTableCount == 1 {
		if err := database.Raw(`SELECT
			singleton, active_key_id, revision,
			typeof(singleton) AS singleton_type,
			typeof(active_key_id) AS active_key_id_type,
			typeof(revision) AS revision_type
			FROM o_smb_credential_key_control ORDER BY singleton`).Scan(&snapshot.Controls).Error; err != nil {
			t.Fatal(err)
		}
		if err := database.Raw("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", smbCredentialControlTableName).Scan(&snapshot.ControlTableSQL).Error; err != nil {
			t.Fatal(err)
		}
	}
	return snapshot
}

func assertCutoverPendingControl(t *testing.T, database *gorm.DB, activeKeyID string) {
	t.Helper()
	markers, err := loadSMBCredentialMarkers(database)
	if err != nil || !validPendingSMBCredentialMarker(markers) {
		t.Fatalf("pending marker invalid: %v", err)
	}
	decodedActiveKeyID, decodeErr := decodeSMBCredentialActiveKeyID(activeKeyID)
	if decodeErr != nil {
		t.Fatal(decodeErr)
	}
	defer clear(decodedActiveKeyID)
	controls, err := loadSMBCredentialControls(database)
	if err != nil || !validSMBCredentialControl(controls, decodedActiveKeyID) {
		t.Fatalf("key control invalid: %v", err)
	}
	var storedSQL string
	if err := database.Raw("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?", smbCredentialControlTableName).Scan(&storedSQL).Error; err != nil {
		t.Fatal(err)
	}
	if normalizeSQLiteSQL(storedSQL) != normalizeSQLiteSQL(smbCredentialControlTableSQL) {
		t.Fatal("key control table SQL drifted")
	}
}

func cutoverControlFingerprint(t *testing.T, database *gorm.DB) string {
	t.Helper()
	var fingerprint string
	if err := database.Raw(`SELECT coalesce(group_concat(value, '|'), '') FROM (
		SELECT printf('%s:%s:%s:%s:%s:%s',
			typeof(singleton), quote(singleton),
			typeof(active_key_id), hex(active_key_id),
			typeof(revision), quote(revision)
		) AS value
		FROM o_smb_credential_key_control
		ORDER BY singleton
	)`).Scan(&fingerprint).Error; err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func cutoverTotalChanges(t *testing.T, database *gorm.DB) int64 {
	t.Helper()
	var changes int64
	if err := database.Raw("SELECT total_changes()").Scan(&changes).Error; err != nil {
		t.Fatal(err)
	}
	return changes
}

func cutoverSchemaFingerprint(t *testing.T, database *gorm.DB, schema string) string {
	t.Helper()
	if schema != "main" && schema != "temp" {
		t.Fatalf("unsupported schema %q", schema)
	}
	var fingerprint string
	statement := `SELECT coalesce(group_concat(value, '|'), '') FROM (
		SELECT printf('%s:%s:%s:%s', type, name, tbl_name, coalesce(sql, '')) AS value
		FROM ` + schema + `.sqlite_master
		ORDER BY type, name
	)`
	if err := database.Raw(statement).Scan(&fingerprint).Error; err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func cutoverSchemaVersion(t *testing.T, database *gorm.DB, schema string) int64 {
	t.Helper()
	if schema != "main" && schema != "temp" {
		t.Fatalf("unsupported schema %q", schema)
	}
	var version int64
	if err := database.Raw("PRAGMA " + schema + ".schema_version").Scan(&version).Error; err != nil {
		t.Fatal(err)
	}
	return version
}

func assertLegacyCutoverRollback(t *testing.T, database *gorm.DB, credentials []cutoverTestCredential) {
	t.Helper()
	stored := loadCutoverTestRows(t, database)
	if len(stored) != len(credentials) {
		t.Fatalf("rows after rollback = %d, want %d", len(stored), len(credentials))
	}
	for index := range stored {
		if !stored[index].Password.Valid ||
			stored[index].Password.String != credentials[index].Password ||
			stored[index].CredentialID != "" ||
			stored[index].CredentialFormat != "" ||
			len(stored[index].PasswordEnvelope) != 0 ||
			stored[index].RowRevision != 0 {
			t.Fatalf("row %d was partially cut over", credentials[index].ID)
		}
	}
	assertCutoverMarkerCount(t, database, 0)
	assertCutoverControlTableCount(t, database, 0)
}

func assertCutoverWriterAvailable(t *testing.T, database *gorm.DB) {
	t.Helper()
	if err := database.Exec("BEGIN IMMEDIATE").Error; err != nil {
		t.Fatalf("writer unavailable after rollback: %v", err)
	}
	if err := database.Exec("ROLLBACK").Error; err != nil {
		t.Fatal(err)
	}
}

func assertCutoverMarkerCount(t *testing.T, database *gorm.DB, expected int64) {
	t.Helper()
	var count int64
	if err := database.Raw("SELECT count(*) FROM o_security_migrations").Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("marker count = %d, want %d", count, expected)
	}
}

func assertCutoverControlTableCount(t *testing.T, database *gorm.DB, expected int64) {
	t.Helper()
	var count int64
	if err := database.Raw("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", smbCredentialControlTableName).Scan(&count).Error; err != nil {
		t.Fatal(err)
	}
	if count != expected {
		t.Fatalf("control table count = %d, want %d", count, expected)
	}
}
