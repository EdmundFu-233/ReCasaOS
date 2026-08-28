package sqlite

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IceWhaleTech/CasaOS/pkg/smbcredentials"
	"github.com/IceWhaleTech/CasaOS/service"
	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	maxSMBCredentialRows              = 4096
	maxSMBCredentialPlaintextBytes    = 4 << 20
	maxSMBCredentialMetadataBytes     = 64 << 20
	maxSMBCredentialUsernameBytes     = 255
	maxSMBCredentialPasswordBytes     = 1024
	maxSMBCredentialHostBytes         = 255
	maxSMBCredentialPortBytes         = 3
	maxSMBCredentialDirectoriesBytes  = 16 << 10
	maxSMBCredentialBootIDBytes       = 255
	maxSMBCredentialMountIDsBytes     = 64 << 10
	minSMBCredentialEnvelopeV1Bytes   = 158
	maxSMBCredentialEnvelopeV1Bytes   = 1182
	maxSMBCredentialShares            = 64
	maxSMBCredentialSchemaSQLBytes    = 64 << 10
	maxSMBCredentialSchemaNameBytes   = 255
	maxSMBCredentialSchemaTypeBytes   = 255
	maxSMBCredentialSchemaDefault     = 1024
	maxSMBCredentialConnectionIndexes = 1024
	smbCredentialRollbackTimeout      = 5 * time.Second
	smbCredentialControlTableName     = "o_smb_credential_key_control"
	smbCredentialControlRevision      = 1
)

var errSMBCredentialCutover = errors.New("ReCasaOS SMB credential cutover failed")

// sealedSMBCredentialRowPredicateSQL is only a storage-shape classifier.
// authenticateSealedSMBCredentialRows remains authoritative for the canonical
// UUID, envelope bytes, metadata AAD, and keyring correspondence.
const sealedSMBCredentialRowPredicateSQL = `(
	typeof(id) = 'integer'
	AND id > 0
	AND typeof(username) = 'text'
	AND typeof(password) = 'null'
		AND typeof(host) = 'text'
		AND typeof(port) = 'text'
		AND typeof(directories) = 'text'
		AND typeof(boot_id) = 'text'
		AND typeof(mount_ids) = 'text'
	AND typeof(credential_id) = 'text'
	AND credential_id <> ''
	AND typeof(credential_format) = 'text'
	AND credential_format = 'recasaos-smb-envelope-v1'
	AND typeof(password_envelope) = 'blob'
	AND length(CAST(password_envelope AS BLOB)) > 0
	AND typeof(row_revision) = 'integer'
	AND row_revision = 1
)`

const (
	createSMBCredentialControlTableSQL = `CREATE TABLE IF NOT EXISTS main.o_smb_credential_key_control (
		singleton INTEGER NOT NULL PRIMARY KEY CHECK (
			typeof(singleton) = 'integer'
			AND singleton = 1
		),
		active_key_id BLOB NOT NULL CHECK (
			typeof(active_key_id) = 'blob'
			AND length(active_key_id) = 32
		),
		revision INTEGER NOT NULL CHECK (
			typeof(revision) = 'integer'
			AND revision >= 1
		)
	) WITHOUT ROWID`
	smbCredentialControlTableSQL = `CREATE TABLE o_smb_credential_key_control (
		singleton INTEGER NOT NULL PRIMARY KEY CHECK (
			typeof(singleton) = 'integer'
			AND singleton = 1
		),
		active_key_id BLOB NOT NULL CHECK (
			typeof(active_key_id) = 'blob'
			AND length(active_key_id) = 32
		),
		revision INTEGER NOT NULL CHECK (
			typeof(revision) = 'integer'
			AND revision >= 1
		)
	) WITHOUT ROWID`
)

type smbCredentialCutoverResult struct {
	Migrated bool
	Pending  bool
	Rows     int
}

type smbCredentialCutoverDependencies struct {
	NewCredentialID func() (uuid.UUID, error)
	Now             func() time.Time
}

func defaultSMBCredentialCutoverDependencies() smbCredentialCutoverDependencies {
	return smbCredentialCutoverDependencies{
		NewCredentialID: uuid.NewRandom,
		Now:             time.Now,
	}
}

type smbCredentialStorageCounts struct {
	Total  int64 `gorm:"column:total"`
	Legacy int64 `gorm:"column:legacy"`
	Sealed int64 `gorm:"column:sealed"`
}

type smbCredentialResourceSnapshot struct {
	RowCount            int64 `gorm:"column:row_count"`
	InvalidStorage      int64 `gorm:"column:invalid_storage"`
	PasswordBytes       int64 `gorm:"column:password_bytes"`
	EnvelopeBytes       int64 `gorm:"column:envelope_bytes"`
	MetadataBytes       int64 `gorm:"column:metadata_bytes"`
	MaxUsernameBytes    int64 `gorm:"column:max_username_bytes"`
	MaxPasswordBytes    int64 `gorm:"column:max_password_bytes"`
	MaxHostBytes        int64 `gorm:"column:max_host_bytes"`
	MaxPortBytes        int64 `gorm:"column:max_port_bytes"`
	MaxDirectoriesBytes int64 `gorm:"column:max_directories_bytes"`
	MaxBootIDBytes      int64 `gorm:"column:max_boot_id_bytes"`
	MaxMountIDsBytes    int64 `gorm:"column:max_mount_ids_bytes"`
	MaxCredentialID     int64 `gorm:"column:max_credential_id_bytes"`
	MaxFormatBytes      int64 `gorm:"column:max_format_bytes"`
	MaxEnvelopeBytes    int64 `gorm:"column:max_envelope_bytes"`
	MinEnvelopeBytes    int64 `gorm:"column:min_envelope_bytes"`
}

type smbCredentialStateResourceSnapshot struct {
	RowCount       int64 `gorm:"column:row_count"`
	InvalidStorage int64 `gorm:"column:invalid_storage"`
	MaxFirstBytes  int64 `gorm:"column:max_first_bytes"`
	MaxSecondBytes int64 `gorm:"column:max_second_bytes"`
}

type smbCredentialSchemaResourceSnapshot struct {
	RowCount        int64 `gorm:"column:row_count"`
	InvalidStorage  int64 `gorm:"column:invalid_storage"`
	MaxNameBytes    int64 `gorm:"column:max_name_bytes"`
	MaxTypeBytes    int64 `gorm:"column:max_type_bytes"`
	MaxDefaultBytes int64 `gorm:"column:max_default_bytes"`
	MaxSQLBytes     int64 `gorm:"column:max_sql_bytes"`
}

type sqliteTableXColumn struct {
	CID          int     `gorm:"column:cid"`
	Name         string  `gorm:"column:name"`
	Type         string  `gorm:"column:type"`
	NotNull      int     `gorm:"column:notnull"`
	DefaultValue *string `gorm:"column:dflt_value"`
	PrimaryKey   int     `gorm:"column:pk"`
	Hidden       int     `gorm:"column:hidden"`
}

type smbCredentialMarkerSnapshot struct {
	Name        string `gorm:"column:name"`
	State       string `gorm:"column:state"`
	Updated     int64  `gorm:"column:updated"`
	NameType    string `gorm:"column:name_type"`
	StateType   string `gorm:"column:state_type"`
	UpdatedType string `gorm:"column:updated_type"`
}

type smbCredentialControlSnapshot struct {
	Singleton       int64  `gorm:"column:singleton"`
	ActiveKeyID     []byte `gorm:"column:active_key_id"`
	Revision        int64  `gorm:"column:revision"`
	SingletonType   string `gorm:"column:singleton_type"`
	ActiveKeyIDType string `gorm:"column:active_key_id_type"`
	RevisionType    string `gorm:"column:revision_type"`
}

type legacySMBCredentialRow struct {
	ID             int64
	Username       []byte
	Password       []byte
	Host           []byte
	Port           []byte
	Directories    []byte
	BootID         []byte
	MountIDs       []byte
	NormalizedPort string
}

func (row *legacySMBCredentialRow) destroy() {
	if row == nil {
		return
	}
	clear(row.Password)
	row.Password = nil
}

type sealedSMBCredentialRow struct {
	ID               int64  `gorm:"column:id"`
	Username         string `gorm:"column:username"`
	Host             string `gorm:"column:host"`
	Port             string `gorm:"column:port"`
	Directories      string `gorm:"column:directories"`
	BootID           string `gorm:"column:boot_id"`
	MountIDs         string `gorm:"column:mount_ids"`
	CredentialID     string `gorm:"column:credential_id"`
	CredentialFormat string `gorm:"column:credential_format"`
	PasswordEnvelope []byte `gorm:"column:password_envelope"`
	RowRevision      int64  `gorm:"column:row_revision"`
}

// cutoverSMBCredentials is deliberately not wired into GetDb or startup yet.
// It is the transaction-only part of the future migration: it either resumes
// and authenticates an already-pending sealed database or atomically seals
// every strict legacy row, round-trips every generated envelope, clears every
// plaintext password, and commits a pending marker bound to the active key ID.
// The BEGIN IMMEDIATE transaction is the only writer during classification and
// cutover. A zero-row database is still bound to the expected keyring through
// the singleton control row.
//
// A production caller must still perform the separately reviewed SQLite
// current-file/WAL/journal scrub, reauthenticate the durable result, install a
// cutover-capable runtime DAO, and only then change pending to complete before
// publishing the database or service as ready. This function alone is not a
// deployment or activation boundary.
func cutoverSMBCredentials(database *gorm.DB, keyring *smbcredentials.Keyring) (smbCredentialCutoverResult, error) {
	return cutoverSMBCredentialsWithDependencies(database, keyring, defaultSMBCredentialCutoverDependencies())
}

func cutoverSMBCredentialsWithDependencies(database *gorm.DB, keyring *smbcredentials.Keyring, dependencies smbCredentialCutoverDependencies) (smbCredentialCutoverResult, error) {
	var result smbCredentialCutoverResult
	activeKeyIDText := ""
	if keyring != nil {
		activeKeyIDText = keyring.ActiveID()
	}
	activeKeyID, decodeErr := decodeSMBCredentialActiveKeyID(activeKeyIDText)
	if database == nil || decodeErr != nil || dependencies.NewCredentialID == nil || dependencies.Now == nil {
		return result, errSMBCredentialCutover
	}
	defer clear(activeKeyID)

	session := database.Session(&gorm.Session{Logger: logger.Discard})
	err := withImmediateSMBCredentialTransaction(session, func(transaction *gorm.DB) error {
		if err := verifyNoSMBCredentialTempShadows(transaction); err != nil {
			return cutoverStageError("temporary schema shadow")
		}
		if err := ensureSMBCredentialControlTable(transaction); err != nil {
			return cutoverStageError("control schema")
		}
		if err := verifySMBCredentialCutoverSchema(transaction); err != nil {
			return cutoverStageError("schema")
		}
		counts, err := classifySMBCredentialRows(transaction)
		if err != nil {
			return cutoverStageError("classify rows")
		}
		markers, err := loadSMBCredentialMarkers(transaction)
		if err != nil {
			return cutoverStageError("classify marker")
		}
		controls, err := loadSMBCredentialControls(transaction)
		if err != nil {
			return cutoverStageError("classify control")
		}

		switch {
		case counts.Total == counts.Legacy && len(markers) == 0 && len(controls) == 0:
			rows, migrateErr := migrateLegacySMBCredentialRows(transaction, keyring, activeKeyIDText, activeKeyID, counts.Total, dependencies)
			if migrateErr != nil {
				return migrateErr
			}
			result.Migrated = true
			result.Pending = true
			result.Rows = rows
		case counts.Total == counts.Sealed && validPendingSMBCredentialMarker(markers) && validSMBCredentialControl(controls, activeKeyID):
			rows, authenticateErr := authenticateSealedSMBCredentialRows(transaction, keyring, activeKeyIDText)
			if authenticateErr != nil {
				return authenticateErr
			}
			result.Pending = true
			result.Rows = rows
		default:
			return cutoverStageError("incompatible state")
		}

		if keyring.ActiveID() != activeKeyIDText {
			return cutoverStageError("keyring lifecycle")
		}
		return nil
	})
	if err != nil {
		return smbCredentialCutoverResult{}, normalizeSMBCredentialCutoverError(err)
	}
	return result, nil
}

func verifyNoSMBCredentialTempShadows(database *gorm.DB) error {
	var count int64
	if err := database.Raw(`SELECT count(*) FROM sqlite_temp_master
				WHERE lower(name) IN (?, ?, ?)
				OR (type = 'trigger' AND lower(tbl_name) IN (?, ?, ?))`,
		"o_connections",
		"o_security_migrations",
		smbCredentialControlTableName,
		"o_connections",
		"o_security_migrations",
		smbCredentialControlTableName,
	).Scan(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return errSMBCredentialCutover
	}
	return nil
}

func verifySMBCredentialCutoverSchema(database *gorm.DB) error {
	var canonicalTables int64
	if err := database.Raw(`SELECT count(*) FROM main.sqlite_master
		WHERE type = 'table' AND name IN (?, ?, ?)`,
		"o_connections",
		"o_security_migrations",
		smbCredentialControlTableName,
	).Scan(&canonicalTables).Error; err != nil || canonicalTables != 3 {
		return errSMBCredentialCutover
	}
	if err := preflightSMBCredentialSchemaResources(database); err != nil {
		return err
	}
	if err := verifySMBCredentialSchema(database); err != nil {
		return err
	}
	var columns []sqliteTableXColumn
	if err := database.Raw("PRAGMA main.table_xinfo('o_connections')").Scan(&columns).Error; err != nil {
		return err
	}
	expectedNames := map[string]struct{}{
		"id": {}, "updated": {}, "created": {}, "username": {}, "password": {},
		"credential_id": {}, "credential_format": {}, "password_envelope": {}, "row_revision": {},
		"host": {}, "port": {}, "status": {}, "directories": {}, "mount_point": {}, "boot_id": {}, "mount_ids": {},
	}
	if len(columns) != len(expectedNames) {
		return errSMBCredentialCutover
	}
	seen := make(map[string]struct{}, len(columns))
	baseColumns := make([]sqliteTableColumn, 0, len(columns))
	for _, column := range columns {
		if column.Hidden != 0 {
			return errSMBCredentialCutover
		}
		if _, expected := expectedNames[column.Name]; !expected {
			return errSMBCredentialCutover
		}
		if _, duplicate := seen[column.Name]; duplicate {
			return errSMBCredentialCutover
		}
		seen[column.Name] = struct{}{}
		baseColumns = append(baseColumns, sqliteTableColumn{
			CID:          column.CID,
			Name:         column.Name,
			Type:         column.Type,
			NotNull:      column.NotNull,
			DefaultValue: column.DefaultValue,
			PrimaryKey:   column.PrimaryKey,
		})
	}
	indexedBaseColumns, err := indexSQLiteColumns(baseColumns)
	if err != nil {
		return err
	}
	if err := verifyLegacyConnectionColumns(indexedBaseColumns); err != nil {
		return err
	}
	if err := verifyLegacyConnectionRowID(database); err != nil {
		return err
	}

	var triggerCount int64
	if err := database.Raw(`SELECT count(*) FROM main.sqlite_master
		WHERE type = 'trigger' AND lower(tbl_name) IN (?, ?, ?)`,
		"o_connections",
		"o_security_migrations",
		smbCredentialControlTableName,
	).Scan(&triggerCount).Error; err != nil {
		return err
	}
	if triggerCount != 0 {
		return errSMBCredentialCutover
	}
	if err := verifyNoSMBCredentialForeignKeys(database); err != nil {
		return err
	}
	return nil
}

func verifyNoSMBCredentialForeignKeys(database *gorm.DB) error {
	var count int64
	if err := database.Raw(`SELECT count(*)
		FROM main.sqlite_master AS child
		JOIN pragma_foreign_key_list(child.name, 'main') AS foreign_key
		WHERE child.type = 'table'
		AND (
			lower(child.name) IN (?, ?, ?)
			OR lower(foreign_key."table") IN (?, ?, ?)
		)`,
		"o_connections",
		"o_security_migrations",
		smbCredentialControlTableName,
		"o_connections",
		"o_security_migrations",
		smbCredentialControlTableName,
	).Scan(&count).Error; err != nil {
		return err
	}
	if count != 0 {
		return errSMBCredentialCutover
	}
	return nil
}

func decodeSMBCredentialActiveKeyID(encoded string) ([]byte, error) {
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, errSMBCredentialCutover
	}
	return decoded, nil
}

func withImmediateSMBCredentialTransaction(database *gorm.DB, operation func(*gorm.DB) error) error {
	if database == nil || operation == nil {
		return errSMBCredentialCutover
	}
	return database.Connection(func(connection *gorm.DB) (result error) {
		sqlConnection, operationContext, connectionErr := smbCredentialSQLConnection(connection)
		if connectionErr != nil {
			return cutoverStageError("pin connection")
		}
		if err := configureSMBCredentialCutoverConnection(sqlConnection, operationContext); err != nil {
			return cutoverStageError("configure durable connection")
		}
		if _, err := sqlConnection.ExecContext(operationContext, "BEGIN IMMEDIATE"); err != nil {
			return cutoverStageError("begin immediate")
		}
		transactionOpen := true
		invalidateConnection := false
		defer func() {
			if !transactionOpen {
				return
			}
			cleanupContext, cancelCleanup := context.WithTimeout(context.Background(), smbCredentialRollbackTimeout)
			_, rollbackErr := sqlConnection.ExecContext(cleanupContext, "ROLLBACK")
			cancelCleanup()
			if rollbackErr != nil {
				result = cutoverStageError("transaction outcome unknown")
				invalidateConnection = true
			}
			if invalidateConnection {
				discardSMBCredentialSQLConnection(sqlConnection)
			}
		}()
		if err := operation(connection); err != nil {
			return err
		}
		if _, err := sqlConnection.ExecContext(operationContext, "COMMIT"); err != nil {
			invalidateConnection = true
			return cutoverStageError("commit outcome unknown")
		}
		transactionOpen = false
		return nil
	})
}

func discardSMBCredentialSQLConnection(connection *sql.Conn) {
	if connection == nil {
		return
	}
	_ = connection.Raw(func(any) error {
		return driver.ErrBadConn
	})
}

func configureSMBCredentialCutoverConnection(connection *sql.Conn, operationContext context.Context) error {
	if connection == nil || operationContext == nil {
		return errSMBCredentialCutover
	}
	if err := verifySMBCredentialDatabaseAttachment(connection, operationContext); err != nil {
		return err
	}
	for _, setting := range []struct {
		set  string
		read string
		want int
	}{
		{set: "PRAGMA trusted_schema = OFF", read: "PRAGMA trusted_schema", want: 0},
		{set: "PRAGMA writable_schema = OFF", read: "PRAGMA writable_schema", want: 0},
		{set: "PRAGMA ignore_check_constraints = OFF", read: "PRAGMA ignore_check_constraints", want: 0},
		{set: "PRAGMA foreign_keys = ON", read: "PRAGMA foreign_keys", want: 1},
		{set: "PRAGMA recursive_triggers = OFF", read: "PRAGMA recursive_triggers", want: 0},
	} {
		if _, err := connection.ExecContext(operationContext, setting.set); err != nil {
			return err
		}
		var actual int
		if err := connection.QueryRowContext(operationContext, setting.read).Scan(&actual); err != nil || actual != setting.want {
			return errSMBCredentialCutover
		}
	}
	var journalMode string
	if err := connection.QueryRowContext(operationContext, "PRAGMA main.journal_mode").Scan(&journalMode); err != nil {
		return err
	}
	if !strings.EqualFold(journalMode, "delete") && !strings.EqualFold(journalMode, "wal") {
		return errSMBCredentialCutover
	}
	if _, err := connection.ExecContext(operationContext, "PRAGMA main.synchronous = FULL"); err != nil {
		return err
	}
	var synchronous int
	if err := connection.QueryRowContext(operationContext, "PRAGMA main.synchronous").Scan(&synchronous); err != nil || synchronous != 2 {
		return errSMBCredentialCutover
	}
	if _, err := connection.ExecContext(operationContext, "PRAGMA main.secure_delete = ON"); err != nil {
		return err
	}
	var secureDelete int
	if err := connection.QueryRowContext(operationContext, "PRAGMA main.secure_delete").Scan(&secureDelete); err != nil || secureDelete != 1 {
		return errSMBCredentialCutover
	}
	return nil
}

func verifySMBCredentialDatabaseAttachment(connection *sql.Conn, operationContext context.Context) error {
	rows, err := connection.QueryContext(operationContext, "PRAGMA database_list")
	if err != nil {
		return err
	}
	mainFound := false
	for rows.Next() {
		var sequence int
		var name, path string
		if err := rows.Scan(&sequence, &name, &path); err != nil {
			_ = rows.Close()
			return err
		}
		switch name {
		case "main":
			if mainFound || sequence != 0 || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
				_ = rows.Close()
				return errSMBCredentialCutover
			}
			mainFound = true
		case "temp":
			if path != "" {
				_ = rows.Close()
				return errSMBCredentialCutover
			}
		default:
			_ = rows.Close()
			return errSMBCredentialCutover
		}
	}
	rowsErr := rows.Err()
	closeErr := rows.Close()
	if rowsErr != nil || closeErr != nil || !mainFound {
		return errSMBCredentialCutover
	}
	return nil
}

func smbCredentialSQLConnection(database *gorm.DB) (*sql.Conn, context.Context, error) {
	if database == nil || database.Statement == nil {
		return nil, nil, errSMBCredentialCutover
	}
	connection, ok := database.Statement.ConnPool.(*sql.Conn)
	if !ok || connection == nil {
		return nil, nil, errSMBCredentialCutover
	}
	operationContext := database.Statement.Context
	if operationContext == nil {
		operationContext = context.Background()
	}
	return connection, operationContext, nil
}

func ensureSMBCredentialControlTable(database *gorm.DB) error {
	if result := database.Exec(createSMBCredentialControlTableSQL); result.Error != nil {
		return result.Error
	}
	if err := preflightSMBCredentialSchemaObjectSQL(database, "table", smbCredentialControlTableName); err != nil {
		return err
	}
	if err := preflightSMBCredentialTableColumns(database, smbCredentialControlTableName, 3); err != nil {
		return err
	}
	var storedSQL string
	result := database.Raw(
		"SELECT sql FROM main.sqlite_master WHERE type = ? AND name = ?",
		"table",
		smbCredentialControlTableName,
	).Scan(&storedSQL)
	if result.Error != nil || result.RowsAffected != 1 || normalizeSQLiteSQL(storedSQL) != normalizeSQLiteSQL(smbCredentialControlTableSQL) {
		return errSMBCredentialCutover
	}
	var columns []sqliteTableColumn
	if err := database.Raw("PRAGMA main.table_info('o_smb_credential_key_control')").Scan(&columns).Error; err != nil {
		return err
	}
	expected := []sqliteTableColumn{
		{Name: "singleton", Type: "INTEGER", NotNull: 1, PrimaryKey: 1},
		{Name: "active_key_id", Type: "BLOB", NotNull: 1},
		{Name: "revision", Type: "INTEGER", NotNull: 1},
	}
	if len(columns) != len(expected) {
		return errSMBCredentialCutover
	}
	for index := range expected {
		actual := columns[index]
		want := expected[index]
		if actual.Name != want.Name || actual.Type != want.Type || actual.NotNull != want.NotNull || actual.PrimaryKey != want.PrimaryKey || actual.DefaultValue != nil {
			return errSMBCredentialCutover
		}
	}
	return nil
}

func preflightSMBCredentialSchemaResources(database *gorm.DB) error {
	var objects smbCredentialSchemaResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN typeof(name) = 'text' AND typeof(sql) = 'text' THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(name AS BLOB))), 0) AS max_name_bytes,
		coalesce(max(length(CAST(sql AS BLOB))), 0) AS max_sql_bytes
		FROM main.sqlite_master
		WHERE (type = 'table' AND name IN ('o_connections', 'o_security_migrations'))
		OR (type = 'index' AND name = ?)`, smbCredentialIDIndexName).Scan(&objects).Error; err != nil {
		return err
	}
	if objects.RowCount != 3 || objects.InvalidStorage != 0 ||
		objects.MaxNameBytes < 0 || objects.MaxNameBytes > maxSMBCredentialSchemaNameBytes ||
		objects.MaxSQLBytes <= 0 || objects.MaxSQLBytes > maxSMBCredentialSchemaSQLBytes {
		return errSMBCredentialCutover
	}
	for _, table := range []struct {
		name    string
		columns int64
	}{
		{name: "o_connections", columns: 16},
		{name: "o_security_migrations", columns: 3},
	} {
		if err := preflightSMBCredentialTableColumns(database, table.name, table.columns); err != nil {
			return err
		}
	}

	var indexes smbCredentialSchemaResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN typeof(name) = 'text' AND typeof(origin) = 'text' THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(name AS BLOB))), 0) AS max_name_bytes,
		coalesce(max(length(CAST(origin AS BLOB))), 0) AS max_type_bytes
		FROM pragma_index_list('o_connections', 'main')`).Scan(&indexes).Error; err != nil {
		return err
	}
	if indexes.RowCount < 1 || indexes.RowCount > maxSMBCredentialConnectionIndexes || indexes.InvalidStorage != 0 ||
		indexes.MaxNameBytes < 0 || indexes.MaxNameBytes > maxSMBCredentialSchemaNameBytes ||
		indexes.MaxTypeBytes < 0 || indexes.MaxTypeBytes > maxSMBCredentialSchemaTypeBytes {
		return errSMBCredentialCutover
	}

	var indexColumns smbCredentialSchemaResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN typeof(name) = 'text' THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(name AS BLOB))), 0) AS max_name_bytes
		FROM pragma_index_info(?, 'main')`, smbCredentialIDIndexName).Scan(&indexColumns).Error; err != nil {
		return err
	}
	if indexColumns.RowCount != 1 || indexColumns.InvalidStorage != 0 ||
		indexColumns.MaxNameBytes < 0 || indexColumns.MaxNameBytes > maxSMBCredentialSchemaNameBytes {
		return errSMBCredentialCutover
	}
	return nil
}

func preflightSMBCredentialSchemaObjectSQL(database *gorm.DB, objectType, objectName string) error {
	var snapshot smbCredentialSchemaResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN typeof(name) = 'text' AND typeof(sql) = 'text' THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(name AS BLOB))), 0) AS max_name_bytes,
		coalesce(max(length(CAST(sql AS BLOB))), 0) AS max_sql_bytes
		FROM main.sqlite_master WHERE type = ? AND name = ?`, objectType, objectName).Scan(&snapshot).Error; err != nil {
		return err
	}
	if snapshot.RowCount != 1 || snapshot.InvalidStorage != 0 ||
		snapshot.MaxNameBytes < 0 || snapshot.MaxNameBytes > maxSMBCredentialSchemaNameBytes ||
		snapshot.MaxSQLBytes <= 0 || snapshot.MaxSQLBytes > maxSMBCredentialSchemaSQLBytes {
		return errSMBCredentialCutover
	}
	return nil
}

func preflightSMBCredentialTableColumns(database *gorm.DB, tableName string, expectedColumns int64) error {
	var snapshot smbCredentialSchemaResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN
			typeof(name) = 'text'
			AND typeof(type) = 'text'
			AND (dflt_value IS NULL OR typeof(dflt_value) = 'text')
			THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(name AS BLOB))), 0) AS max_name_bytes,
		coalesce(max(length(CAST(type AS BLOB))), 0) AS max_type_bytes,
		coalesce(max(length(CAST(dflt_value AS BLOB))), 0) AS max_default_bytes
		FROM pragma_table_xinfo(?, 'main')`, tableName).Scan(&snapshot).Error; err != nil {
		return err
	}
	if snapshot.RowCount != expectedColumns || snapshot.InvalidStorage != 0 ||
		snapshot.MaxNameBytes < 0 || snapshot.MaxNameBytes > maxSMBCredentialSchemaNameBytes ||
		snapshot.MaxTypeBytes < 0 || snapshot.MaxTypeBytes > maxSMBCredentialSchemaTypeBytes ||
		snapshot.MaxDefaultBytes < 0 || snapshot.MaxDefaultBytes > maxSMBCredentialSchemaDefault {
		return errSMBCredentialCutover
	}
	return nil
}

func classifySMBCredentialRows(database *gorm.DB) (smbCredentialStorageCounts, error) {
	var counts smbCredentialStorageCounts
	statement := `SELECT
		count(*) AS total,
		coalesce(sum(CASE WHEN ` + model2.LegacySMBCredentialRowPredicateSQL + ` THEN 1 ELSE 0 END), 0) AS legacy,
		coalesce(sum(CASE WHEN ` + sealedSMBCredentialRowPredicateSQL + ` THEN 1 ELSE 0 END), 0) AS sealed
		FROM main.o_connections`
	if err := database.Raw(statement).Scan(&counts).Error; err != nil {
		return smbCredentialStorageCounts{}, err
	}
	if counts.Total < 0 || counts.Legacy < 0 || counts.Sealed < 0 || counts.Legacy > counts.Total || counts.Sealed > counts.Total || counts.Legacy+counts.Sealed > counts.Total || counts.Total > maxSMBCredentialRows {
		return smbCredentialStorageCounts{}, errSMBCredentialCutover
	}
	return counts, nil
}

func preflightLegacySMBCredentialRows(database *gorm.DB, expectedRows int64) error {
	var snapshot smbCredentialResourceSnapshot
	statement := `SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN
			typeof(id) = 'integer' AND id > 0
			AND typeof(username) = 'text'
			AND typeof(password) = 'text'
			AND typeof(host) = 'text'
			AND typeof(port) = 'text'
			AND typeof(directories) = 'text'
			AND typeof(boot_id) = 'text'
			AND typeof(mount_ids) = 'text'
			AND (credential_id IS NULL OR (typeof(credential_id) = 'text' AND credential_id = ''))
			AND (credential_format IS NULL OR (typeof(credential_format) = 'text' AND credential_format = ''))
			AND (password_envelope IS NULL OR (typeof(password_envelope) = 'blob' AND length(password_envelope) = 0))
			AND typeof(row_revision) = 'integer' AND row_revision = 0
			THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(sum(length(CAST(password AS BLOB))), 0) AS password_bytes,
		coalesce(sum(
			length(CAST(username AS BLOB)) +
			length(CAST(host AS BLOB)) +
			length(CAST(port AS BLOB)) +
			length(CAST(directories AS BLOB)) +
			length(CAST(boot_id AS BLOB)) +
			length(CAST(mount_ids AS BLOB))
		), 0) AS metadata_bytes,
		coalesce(max(length(CAST(username AS BLOB))), 0) AS max_username_bytes,
		coalesce(max(length(CAST(password AS BLOB))), 0) AS max_password_bytes,
		coalesce(max(length(CAST(host AS BLOB))), 0) AS max_host_bytes,
		coalesce(max(length(CAST(port AS BLOB))), 0) AS max_port_bytes,
		coalesce(max(length(CAST(directories AS BLOB))), 0) AS max_directories_bytes,
		coalesce(max(length(CAST(boot_id AS BLOB))), 0) AS max_boot_id_bytes,
		coalesce(max(length(CAST(mount_ids AS BLOB))), 0) AS max_mount_ids_bytes
		FROM main.o_connections
		WHERE ` + model2.LegacySMBCredentialRowPredicateSQL
	if err := database.Raw(statement).Scan(&snapshot).Error; err != nil {
		return err
	}
	if snapshot.RowCount != expectedRows ||
		snapshot.InvalidStorage != 0 ||
		snapshot.PasswordBytes < 0 || snapshot.PasswordBytes > maxSMBCredentialPlaintextBytes ||
		snapshot.MetadataBytes < 0 || snapshot.MetadataBytes > maxSMBCredentialMetadataBytes ||
		snapshot.MaxUsernameBytes < 0 || snapshot.MaxUsernameBytes > maxSMBCredentialUsernameBytes ||
		snapshot.MaxPasswordBytes < 0 || snapshot.MaxPasswordBytes > maxSMBCredentialPasswordBytes ||
		snapshot.MaxHostBytes < 0 || snapshot.MaxHostBytes > maxSMBCredentialHostBytes ||
		snapshot.MaxPortBytes < 0 || snapshot.MaxPortBytes > maxSMBCredentialPortBytes ||
		snapshot.MaxDirectoriesBytes < 0 || snapshot.MaxDirectoriesBytes > maxSMBCredentialDirectoriesBytes ||
		snapshot.MaxBootIDBytes < 0 || snapshot.MaxBootIDBytes > maxSMBCredentialBootIDBytes ||
		snapshot.MaxMountIDsBytes < 0 || snapshot.MaxMountIDsBytes > maxSMBCredentialMountIDsBytes {
		return errSMBCredentialCutover
	}
	return nil
}

func preflightSealedSMBCredentialRows(database *gorm.DB, expectedRows int64) error {
	var snapshot smbCredentialResourceSnapshot
	statement := `SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN ` + sealedSMBCredentialRowPredicateSQL + ` THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(sum(
			length(CAST(username AS BLOB)) +
			length(CAST(host AS BLOB)) +
			length(CAST(port AS BLOB)) +
			length(CAST(directories AS BLOB)) +
			length(CAST(boot_id AS BLOB)) +
			length(CAST(mount_ids AS BLOB)) +
			length(CAST(credential_id AS BLOB)) +
			length(CAST(credential_format AS BLOB))
		), 0) AS metadata_bytes,
		coalesce(sum(length(password_envelope)), 0) AS envelope_bytes,
		coalesce(max(length(CAST(username AS BLOB))), 0) AS max_username_bytes,
		coalesce(max(length(CAST(host AS BLOB))), 0) AS max_host_bytes,
		coalesce(max(length(CAST(port AS BLOB))), 0) AS max_port_bytes,
		coalesce(max(length(CAST(directories AS BLOB))), 0) AS max_directories_bytes,
		coalesce(max(length(CAST(boot_id AS BLOB))), 0) AS max_boot_id_bytes,
		coalesce(max(length(CAST(mount_ids AS BLOB))), 0) AS max_mount_ids_bytes,
		coalesce(max(length(CAST(credential_id AS BLOB))), 0) AS max_credential_id_bytes,
		coalesce(max(length(CAST(credential_format AS BLOB))), 0) AS max_format_bytes,
		coalesce(max(length(password_envelope)), 0) AS max_envelope_bytes,
		coalesce(min(length(password_envelope)), 0) AS min_envelope_bytes
		FROM main.o_connections`
	if err := database.Raw(statement).Scan(&snapshot).Error; err != nil {
		return err
	}
	if snapshot.RowCount != expectedRows ||
		snapshot.InvalidStorage != 0 ||
		snapshot.MetadataBytes < 0 || snapshot.MetadataBytes > maxSMBCredentialMetadataBytes ||
		snapshot.EnvelopeBytes < 0 || snapshot.EnvelopeBytes > maxSMBCredentialEnvelopeV1Bytes*expectedRows ||
		snapshot.MaxUsernameBytes < 0 || snapshot.MaxUsernameBytes > maxSMBCredentialUsernameBytes ||
		snapshot.MaxHostBytes < 0 || snapshot.MaxHostBytes > maxSMBCredentialHostBytes ||
		snapshot.MaxPortBytes < 0 || snapshot.MaxPortBytes > maxSMBCredentialPortBytes ||
		snapshot.MaxDirectoriesBytes < 0 || snapshot.MaxDirectoriesBytes > maxSMBCredentialDirectoriesBytes ||
		snapshot.MaxBootIDBytes < 0 || snapshot.MaxBootIDBytes > maxSMBCredentialBootIDBytes ||
		snapshot.MaxMountIDsBytes < 0 || snapshot.MaxMountIDsBytes > maxSMBCredentialMountIDsBytes ||
		snapshot.MaxCredentialID < 0 || snapshot.MaxCredentialID > 36 ||
		snapshot.MaxFormatBytes < 0 || snapshot.MaxFormatBytes > int64(len(smbcredentials.EnvelopeFormat)) ||
		snapshot.MaxEnvelopeBytes < 0 || snapshot.MaxEnvelopeBytes > maxSMBCredentialEnvelopeV1Bytes ||
		(expectedRows > 0 && snapshot.MinEnvelopeBytes < minSMBCredentialEnvelopeV1Bytes) {
		return errSMBCredentialCutover
	}
	return nil
}

func loadSMBCredentialMarkers(database *gorm.DB) ([]smbCredentialMarkerSnapshot, error) {
	var resources smbCredentialStateResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN
			typeof(name) = 'text'
			AND typeof(state) = 'text'
			AND typeof(updated) = 'integer'
			THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(name AS BLOB))), 0) AS max_first_bytes,
		coalesce(max(length(CAST(state AS BLOB))), 0) AS max_second_bytes
		FROM main.o_security_migrations`).Scan(&resources).Error; err != nil {
		return nil, err
	}
	if resources.RowCount < 0 || resources.RowCount > 1 || resources.InvalidStorage != 0 ||
		resources.MaxFirstBytes < 0 || resources.MaxFirstBytes > int64(len(model2.SMBCredentialMigrationName)) ||
		resources.MaxSecondBytes < 0 || resources.MaxSecondBytes > int64(len(model2.SecurityMigrationComplete)) {
		return nil, errSMBCredentialCutover
	}
	markers := make([]smbCredentialMarkerSnapshot, 0, 2)
	if err := database.Raw(`SELECT
		name, state, updated,
		typeof(name) AS name_type,
		typeof(state) AS state_type,
		typeof(updated) AS updated_type
		FROM main.o_security_migrations
		ORDER BY name
		LIMIT 2`).Scan(&markers).Error; err != nil {
		return nil, err
	}
	return markers, nil
}

func validPendingSMBCredentialMarker(markers []smbCredentialMarkerSnapshot) bool {
	return len(markers) == 1 &&
		markers[0].Name == model2.SMBCredentialMigrationName &&
		markers[0].State == model2.SecurityMigrationPending &&
		markers[0].Updated > 0 &&
		markers[0].NameType == "text" &&
		markers[0].StateType == "text" &&
		markers[0].UpdatedType == "integer"
}

func loadSMBCredentialControls(database *gorm.DB) ([]smbCredentialControlSnapshot, error) {
	var resources smbCredentialStateResourceSnapshot
	if err := database.Raw(`SELECT
		count(*) AS row_count,
		coalesce(sum(CASE WHEN
			typeof(singleton) = 'integer'
			AND typeof(active_key_id) = 'blob'
			AND typeof(revision) = 'integer'
			THEN 0 ELSE 1 END), 0) AS invalid_storage,
		coalesce(max(length(CAST(active_key_id AS BLOB))), 0) AS max_first_bytes
		FROM main.o_smb_credential_key_control`).Scan(&resources).Error; err != nil {
		return nil, err
	}
	if resources.RowCount < 0 || resources.RowCount > 1 || resources.InvalidStorage != 0 ||
		resources.MaxFirstBytes < 0 || resources.MaxFirstBytes > 32 {
		return nil, errSMBCredentialCutover
	}
	controls := make([]smbCredentialControlSnapshot, 0, 2)
	if err := database.Raw(`SELECT
		singleton, active_key_id, revision,
		typeof(singleton) AS singleton_type,
		typeof(active_key_id) AS active_key_id_type,
		typeof(revision) AS revision_type
		FROM main.o_smb_credential_key_control
		ORDER BY singleton
		LIMIT 2`).Scan(&controls).Error; err != nil {
		return nil, err
	}
	return controls, nil
}

func validSMBCredentialControl(controls []smbCredentialControlSnapshot, activeKeyID []byte) bool {
	return len(controls) == 1 &&
		controls[0].Singleton == 1 &&
		bytes.Equal(controls[0].ActiveKeyID, activeKeyID) &&
		controls[0].Revision == smbCredentialControlRevision &&
		controls[0].SingletonType == "integer" &&
		controls[0].ActiveKeyIDType == "blob" &&
		controls[0].RevisionType == "integer"
}

func migrateLegacySMBCredentialRows(database *gorm.DB, keyring *smbcredentials.Keyring, activeKeyIDText string, activeKeyID []byte, expectedRows int64, dependencies smbCredentialCutoverDependencies) (int, error) {
	if expectedRows < 0 || expectedRows > maxSMBCredentialRows {
		return 0, cutoverStageError("legacy row bound")
	}
	rows, err := loadLegacySMBCredentialRows(database, expectedRows)
	if err != nil {
		return 0, cutoverStageError("load legacy rows")
	}
	defer destroyLegacySMBCredentialRows(rows)

	markerTime := dependencies.Now().Unix()
	if markerTime <= 0 {
		return 0, cutoverStageError("marker time")
	}
	sqlConnection, operationContext, err := smbCredentialSQLConnection(database)
	if err != nil {
		return 0, cutoverStageError("pin migration connection")
	}
	markerInsert, err := sqlConnection.ExecContext(operationContext,
		`INSERT INTO main.o_security_migrations(name, state, updated) VALUES (?, ?, ?)`,
		model2.SMBCredentialMigrationName,
		model2.SecurityMigrationPending,
		markerTime,
	)
	if err != nil || requireOneSMBCredentialSQLMutation(markerInsert) != nil {
		return 0, cutoverStageError("create pending marker")
	}
	controlInsert, err := sqlConnection.ExecContext(operationContext,
		`INSERT INTO main.o_smb_credential_key_control(singleton, active_key_id, revision) VALUES (?, ?, ?)`,
		1,
		activeKeyID,
		smbCredentialControlRevision,
	)
	if err != nil || requireOneSMBCredentialSQLMutation(controlInsert) != nil {
		return 0, cutoverStageError("create key control")
	}

	for index := range rows {
		if err := sealLegacySMBCredentialRow(database, keyring, &rows[index], dependencies.NewCredentialID); err != nil {
			return 0, err
		}
		rows[index].destroy()
	}
	if len(rows) != int(expectedRows) {
		return 0, cutoverStageError("legacy row count")
	}

	authenticatedRows, err := authenticateSealedSMBCredentialRows(database, keyring, activeKeyIDText)
	if err != nil || authenticatedRows != len(rows) {
		return 0, cutoverStageError("authenticate migrated rows")
	}
	finalCounts, err := classifySMBCredentialRows(database)
	if err != nil || finalCounts.Total != expectedRows || finalCounts.Sealed != finalCounts.Total {
		return 0, cutoverStageError("verify sealed state")
	}
	markers, err := loadSMBCredentialMarkers(database)
	if err != nil || !validPendingSMBCredentialMarker(markers) {
		return 0, cutoverStageError("verify pending marker")
	}
	controls, err := loadSMBCredentialControls(database)
	if err != nil || !validSMBCredentialControl(controls, activeKeyID) {
		return 0, cutoverStageError("verify key control")
	}
	return len(rows), nil
}

func requireOneSMBCredentialSQLMutation(result sql.Result) error {
	if result == nil {
		return errSMBCredentialCutover
	}
	rows, err := result.RowsAffected()
	if err != nil || rows != 1 {
		return errSMBCredentialCutover
	}
	return nil
}

func loadLegacySMBCredentialRows(database *gorm.DB, expectedRows int64) ([]legacySMBCredentialRow, error) {
	if err := preflightLegacySMBCredentialRows(database, expectedRows); err != nil {
		return nil, err
	}
	queryRows, err := database.Raw(`SELECT
			id, username, password, host, port, directories, boot_id, mount_ids,
			typeof(id), typeof(username), typeof(password), typeof(host), typeof(port), typeof(directories), typeof(boot_id), typeof(mount_ids)
			FROM main.o_connections
		ORDER BY id
		LIMIT ?`, maxSMBCredentialRows+1).Rows()
	if err != nil {
		return nil, err
	}
	defer queryRows.Close()

	rows := make([]legacySMBCredentialRow, 0, expectedRows)
	totalPlaintextBytes := 0
	for queryRows.Next() {
		var row legacySMBCredentialRow
		var idType, usernameType, passwordType, hostType, portType, directoriesType, bootIDType, mountIDsType string
		if err := queryRows.Scan(
			&row.ID,
			&row.Username,
			&row.Password,
			&row.Host,
			&row.Port,
			&row.Directories,
			&row.BootID,
			&row.MountIDs,
			&idType,
			&usernameType,
			&passwordType,
			&hostType,
			&portType,
			&directoriesType,
			&bootIDType,
			&mountIDsType,
		); err != nil {
			row.destroy()
			destroyLegacySMBCredentialRows(rows)
			return nil, err
		}
		if row.ID <= 0 || idType != "integer" || usernameType != "text" || passwordType != "text" || hostType != "text" || portType != "text" || directoriesType != "text" || bootIDType != "text" || mountIDsType != "text" {
			row.destroy()
			destroyLegacySMBCredentialRows(rows)
			return nil, errSMBCredentialCutover
		}
		normalizedPort, validationErr := validateSMBCredentialRuntimeFields(
			row.Username,
			row.Password,
			row.Host,
			row.Port,
			row.Directories,
			row.BootID,
			row.MountIDs,
		)
		if validationErr != nil {
			row.destroy()
			destroyLegacySMBCredentialRows(rows)
			return nil, errSMBCredentialCutover
		}
		row.NormalizedPort = normalizedPort
		totalPlaintextBytes += len(row.Password)
		if len(rows) >= maxSMBCredentialRows || totalPlaintextBytes > maxSMBCredentialPlaintextBytes {
			row.destroy()
			destroyLegacySMBCredentialRows(rows)
			return nil, errSMBCredentialCutover
		}
		rows = append(rows, row)
	}
	if err := queryRows.Err(); err != nil {
		destroyLegacySMBCredentialRows(rows)
		return nil, err
	}
	if err := queryRows.Close(); err != nil {
		destroyLegacySMBCredentialRows(rows)
		return nil, err
	}
	if int64(len(rows)) != expectedRows {
		destroyLegacySMBCredentialRows(rows)
		return nil, errSMBCredentialCutover
	}
	return rows, nil
}

func validateSMBCredentialRuntimeFields(username, password, host, port, directories, bootID, mountIDs []byte) (string, error) {
	normalizedPort := string(port)
	parsedDirectories, _, parsedPort, legacy, err := service.ParsePersistedSambaConnection(
		string(directories),
		normalizedPort,
		string(bootID),
		string(mountIDs),
		maxSMBCredentialShares,
	)
	if err != nil {
		return "", err
	}
	if len(parsedDirectories) == 0 {
		return "", errSMBCredentialCutover
	}
	if !legacy {
		parsedMountIDs, parseErr := service.ParseSambaMountIDs(string(mountIDs), maxSMBCredentialShares)
		if parseErr != nil || len(parsedMountIDs) != len(parsedDirectories) {
			return "", errSMBCredentialCutover
		}
		for _, directory := range parsedDirectories {
			if parsedMountIDs[directory] == 0 {
				return "", errSMBCredentialCutover
			}
		}
	}
	normalizedPort = parsedPort
	if err := service.ValidateSambaConnectionFields(string(username), "", string(host), normalizedPort); err != nil {
		return "", err
	}
	if len(password) > maxSMBCredentialPasswordBytes || !utf8.Valid(password) || bytes.ContainsAny(password, ",\x00\r\n") {
		return "", errSMBCredentialCutover
	}
	for remaining := password; len(remaining) > 0; {
		character, size := utf8.DecodeRune(remaining)
		if size == 0 || character == utf8.RuneError && size == 1 || unicode.IsControl(character) {
			return "", errSMBCredentialCutover
		}
		remaining = remaining[size:]
	}
	return normalizedPort, nil
}

func destroyLegacySMBCredentialRows(rows []legacySMBCredentialRow) {
	for index := range rows {
		rows[index].destroy()
	}
}

func sealLegacySMBCredentialRow(database *gorm.DB, keyring *smbcredentials.Keyring, row *legacySMBCredentialRow, newCredentialID func() (uuid.UUID, error)) error {
	if row == nil || newCredentialID == nil {
		return cutoverStageError("nil legacy row")
	}
	normalizedPort := row.NormalizedPort
	if normalizedPort != "445" {
		return cutoverStageError("legacy runtime validation")
	}
	credentialUUID, err := newCredentialID()
	if err != nil {
		return cutoverStageError("credential identity")
	}
	context := smbcredentials.Context{
		CredentialID: credentialUUID.String(),
		Username:     string(row.Username),
		Host:         string(row.Host),
		Port:         normalizedPort,
		Directories:  string(row.Directories),
	}
	envelope, err := keyring.Seal(context, row.Password)
	if err != nil {
		return cutoverStageError("seal legacy row")
	}
	defer clear(envelope)
	opened, err := keyring.Open(context, envelope)
	if err != nil || !bytes.Equal(opened, row.Password) {
		clear(opened)
		return cutoverStageError("round-trip legacy row")
	}
	clear(opened)

	sqlConnection, operationContext, connectionErr := smbCredentialSQLConnection(database)
	if connectionErr != nil {
		return cutoverStageError("pin row connection")
	}
	update, updateErr := sqlConnection.ExecContext(operationContext, `UPDATE main.o_connections SET
		password = NULL,
		port = ?,
		credential_id = ?,
		credential_format = ?,
		password_envelope = ?,
		row_revision = 1
		WHERE id = ?
		AND `+model2.LegacySMBCredentialRowPredicateSQL+`
		AND typeof(username) = 'text' AND username = CAST(? AS TEXT)
		AND typeof(password) = 'text' AND password = CAST(? AS TEXT)
		AND typeof(host) = 'text' AND host = CAST(? AS TEXT)
			AND typeof(port) = 'text' AND port = CAST(? AS TEXT)
			AND typeof(directories) = 'text' AND directories = CAST(? AS TEXT)
			AND typeof(boot_id) = 'text' AND boot_id = CAST(? AS TEXT)
			AND typeof(mount_ids) = 'text' AND mount_ids = CAST(? AS TEXT)`,
		normalizedPort,
		context.CredentialID,
		smbcredentials.EnvelopeFormat,
		envelope,
		row.ID,
		row.Username,
		row.Password,
		row.Host,
		row.Port,
		row.Directories,
		row.BootID,
		row.MountIDs,
	)
	if updateErr != nil {
		return cutoverStageError("seal legacy row update")
	}
	if requireOneSMBCredentialSQLMutation(update) != nil {
		return cutoverStageError("compare-and-seal legacy row")
	}
	return nil
}

func authenticateSealedSMBCredentialRows(database *gorm.DB, keyring *smbcredentials.Keyring, activeKeyID string) (int, error) {
	counts, err := classifySMBCredentialRows(database)
	if err != nil || counts.Total != counts.Sealed {
		return 0, cutoverStageError("preflight sealed classification")
	}
	if err := preflightSealedSMBCredentialRows(database, counts.Total); err != nil {
		return 0, cutoverStageError("preflight sealed resources")
	}
	rows, err := database.Raw(`SELECT
			id, username, host, port, directories, boot_id, mount_ids,
			credential_id, credential_format, password_envelope, row_revision
		FROM main.o_connections
		WHERE `+sealedSMBCredentialRowPredicateSQL+`
		ORDER BY id
		LIMIT ?`, maxSMBCredentialRows+1).Rows()
	if err != nil {
		return 0, cutoverStageError("load sealed rows")
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		if count >= maxSMBCredentialRows {
			return 0, cutoverStageError("sealed row bound")
		}
		var row sealedSMBCredentialRow
		if err := rows.Scan(
			&row.ID,
			&row.Username,
			&row.Host,
			&row.Port,
			&row.Directories,
			&row.BootID,
			&row.MountIDs,
			&row.CredentialID,
			&row.CredentialFormat,
			&row.PasswordEnvelope,
			&row.RowRevision,
		); err != nil {
			return 0, cutoverStageError("scan sealed row")
		}
		if row.ID <= 0 || row.RowRevision != 1 || row.CredentialFormat != smbcredentials.EnvelopeFormat {
			clear(row.PasswordEnvelope)
			return 0, cutoverStageError("validate sealed row")
		}
		normalizedPort, metadataErr := validateSMBCredentialRuntimeFields(
			[]byte(row.Username),
			nil,
			[]byte(row.Host),
			[]byte(row.Port),
			[]byte(row.Directories),
			[]byte(row.BootID),
			[]byte(row.MountIDs),
		)
		if metadataErr != nil || normalizedPort != row.Port {
			clear(row.PasswordEnvelope)
			return 0, cutoverStageError("validate sealed runtime metadata")
		}
		context := smbcredentials.Context{
			CredentialID: row.CredentialID,
			Username:     row.Username,
			Host:         row.Host,
			Port:         row.Port,
			Directories:  row.Directories,
		}
		plaintext, openErr := keyring.Open(context, row.PasswordEnvelope)
		if openErr != nil {
			clear(plaintext)
			clear(row.PasswordEnvelope)
			return 0, cutoverStageError("authenticate sealed row")
		}
		if _, validationErr := validateSMBCredentialRuntimeFields(
			[]byte(row.Username),
			plaintext,
			[]byte(row.Host),
			[]byte(row.Port),
			[]byte(row.Directories),
			[]byte(row.BootID),
			[]byte(row.MountIDs),
		); validationErr != nil {
			clear(plaintext)
			clear(row.PasswordEnvelope)
			return 0, cutoverStageError("validate sealed runtime credential")
		}
		clear(plaintext)
		envelopeKeyID, keyIDErr := keyring.EnvelopeKeyID(context, row.PasswordEnvelope)
		clear(row.PasswordEnvelope)
		if keyIDErr != nil || envelopeKeyID != activeKeyID {
			return 0, cutoverStageError("bind sealed row key")
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return 0, cutoverStageError("iterate sealed rows")
	}
	if err := rows.Close(); err != nil {
		return 0, cutoverStageError("close sealed rows")
	}
	counts, err = classifySMBCredentialRows(database)
	if err != nil || counts.Total != int64(count) || counts.Sealed != counts.Total {
		return 0, cutoverStageError("authoritative sealed count")
	}
	return count, nil
}

func cutoverStageError(stage string) error {
	return fmt.Errorf("%w: %s", errSMBCredentialCutover, stage)
}

func normalizeSMBCredentialCutoverError(err error) error {
	if errors.Is(err, errSMBCredentialCutover) {
		return err
	}
	return errSMBCredentialCutover
}
