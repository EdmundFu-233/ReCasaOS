package sqlite

import (
	"errors"
	"fmt"
	"strings"

	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"gorm.io/gorm"
)

const (
	smbCredentialIDIndexName = "ux_o_connections_credential_id"

	addConnectionBootIDSQL      = `ALTER TABLE o_connections ADD COLUMN boot_id TEXT`
	addConnectionMountIDsSQL    = `ALTER TABLE o_connections ADD COLUMN mount_ids TEXT`
	addCredentialIDSQL          = `ALTER TABLE o_connections ADD COLUMN credential_id TEXT`
	addCredentialFormatSQL      = `ALTER TABLE o_connections ADD COLUMN credential_format TEXT`
	addPasswordEnvelopeSQL      = `ALTER TABLE o_connections ADD COLUMN password_envelope BLOB`
	addConnectionRowRevisionSQL = `ALTER TABLE o_connections ADD COLUMN row_revision INTEGER NOT NULL DEFAULT 0`

	createSecurityMigrationsTableSQL = `CREATE TABLE IF NOT EXISTS o_security_migrations (
		name TEXT NOT NULL PRIMARY KEY,
		state TEXT NOT NULL CHECK (state IN ('pending', 'complete')),
		updated INTEGER NOT NULL
	) WITHOUT ROWID`
	securityMigrationsTableSQL = `CREATE TABLE o_security_migrations (
		name TEXT NOT NULL PRIMARY KEY,
		state TEXT NOT NULL CHECK (state IN ('pending', 'complete')),
		updated INTEGER NOT NULL
	) WITHOUT ROWID`

	createCredentialIDIndexSQL = `CREATE UNIQUE INDEX IF NOT EXISTS ux_o_connections_credential_id
		ON o_connections(credential_id)
		WHERE credential_id IS NOT NULL AND credential_id <> ''`
	credentialIDIndexSQL = `CREATE UNIQUE INDEX ux_o_connections_credential_id
		ON o_connections(credential_id)
		WHERE credential_id IS NOT NULL AND credential_id <> ''`
)

type sqliteTableColumn struct {
	CID          int     `gorm:"column:cid"`
	Name         string  `gorm:"column:name"`
	Type         string  `gorm:"column:type"`
	NotNull      int     `gorm:"column:notnull"`
	DefaultValue *string `gorm:"column:dflt_value"`
	PrimaryKey   int     `gorm:"column:pk"`
}

type sqliteIndexListEntry struct {
	Sequence int    `gorm:"column:seq"`
	Name     string `gorm:"column:name"`
	Unique   int    `gorm:"column:unique"`
	Origin   string `gorm:"column:origin"`
	Partial  int    `gorm:"column:partial"`
}

type sqliteIndexColumn struct {
	Sequence int    `gorm:"column:seqno"`
	CID      int    `gorm:"column:cid"`
	Name     string `gorm:"column:name"`
}

// expandSMBCredentialSchema is deliberately expand-only. It preserves the
// prior additive boot/mount metadata, adds nullable envelope columns, a
// revision default for legacy rows, and the durable marker table. It neither
// creates a marker nor reads, encrypts, or clears any password. A later
// fail-closed cutover owns those operations.
func expandSMBCredentialSchema(database *gorm.DB) error {
	if database == nil {
		return errors.New("nil SQLite database")
	}
	return database.Transaction(func(transaction *gorm.DB) error {
		if err := ensureSMBCredentialColumns(transaction); err != nil {
			return fmt.Errorf("expand o_connections columns: %w", err)
		}
		if result := transaction.Exec(createSecurityMigrationsTableSQL); result.Error != nil {
			return fmt.Errorf("create security migration table: %w", result.Error)
		}
		if result := transaction.Exec(createCredentialIDIndexSQL); result.Error != nil {
			return fmt.Errorf("create SMB credential identity index: %w", result.Error)
		}
		if err := verifySMBCredentialSchema(transaction); err != nil {
			return fmt.Errorf("verify SMB credential schema: %w", err)
		}
		if err := verifyLegacyOnlySMBCredentialState(transaction); err != nil {
			return fmt.Errorf("verify expand-only SMB credential state: %w", err)
		}
		return nil
	})
}

func ensureSMBCredentialColumns(database *gorm.DB) error {
	var tableCount int64
	if err := database.Raw(
		"SELECT count(*) FROM sqlite_master WHERE type = ? AND name = ?",
		"table",
		(&model2.ConnectionsDBModel{}).TableName(),
	).Scan(&tableCount).Error; err != nil {
		return fmt.Errorf("inspect o_connections existence: %w", err)
	}
	if tableCount == 0 {
		return database.AutoMigrate(&model2.ConnectionsDBModel{})
	}
	if tableCount != 1 {
		return errors.New("ambiguous o_connections table")
	}

	var columns []sqliteTableColumn
	if err := database.Raw("PRAGMA table_info('o_connections')").Scan(&columns).Error; err != nil {
		return fmt.Errorf("inspect o_connections columns: %w", err)
	}
	indexedColumns, err := indexSQLiteColumns(columns)
	if err != nil {
		return err
	}
	if err := verifyLegacyConnectionColumns(indexedColumns); err != nil {
		return err
	}
	if err := verifyLegacyConnectionRowID(database); err != nil {
		return err
	}
	credentialColumns := map[string]struct{}{
		"credential_id":     {},
		"credential_format": {},
		"password_envelope": {},
		"row_revision":      {},
	}
	found := 0
	for _, column := range columns {
		if _, relevant := credentialColumns[column.Name]; relevant {
			found++
		}
	}
	switch found {
	case 0:
		// This is the strict legacy state. Add the credential columns
		// mechanically so historical DDL drift cannot make GORM rebuild the
		// table or discard administrator-owned indexes and triggers.
	case len(credentialColumns):
	default:
		return errors.New("partially expanded o_connections credential schema")
	}

	for _, addition := range []struct {
		name string
		sql  string
	}{
		{name: "boot_id", sql: addConnectionBootIDSQL},
		{name: "mount_ids", sql: addConnectionMountIDsSQL},
	} {
		if _, exists := indexedColumns[addition.name]; exists {
			continue
		}
		if result := database.Exec(addition.sql); result.Error != nil {
			return fmt.Errorf("add o_connections column %s: %w", addition.name, result.Error)
		}
	}
	if found == 0 {
		for _, addition := range []struct {
			name string
			sql  string
		}{
			{name: "credential_id", sql: addCredentialIDSQL},
			{name: "credential_format", sql: addCredentialFormatSQL},
			{name: "password_envelope", sql: addPasswordEnvelopeSQL},
			{name: "row_revision", sql: addConnectionRowRevisionSQL},
		} {
			if result := database.Exec(addition.sql); result.Error != nil {
				return fmt.Errorf("add o_connections column %s: %w", addition.name, result.Error)
			}
		}
	}
	return nil
}

func indexSQLiteColumns(columns []sqliteTableColumn) (map[string]sqliteTableColumn, error) {
	indexed := make(map[string]sqliteTableColumn, len(columns))
	for _, column := range columns {
		if _, duplicate := indexed[column.Name]; duplicate {
			return nil, fmt.Errorf("duplicate SQLite column %s", column.Name)
		}
		indexed[column.Name] = column
	}
	return indexed, nil
}

func verifyLegacyConnectionColumns(columns map[string]sqliteTableColumn) error {
	expected := map[string]sqliteTableColumn{
		"id":          {Type: "INTEGER", PrimaryKey: 1},
		"updated":     {Type: "INTEGER"},
		"created":     {Type: "INTEGER"},
		"username":    {Type: "TEXT"},
		"password":    {Type: "TEXT"},
		"host":        {Type: "TEXT"},
		"port":        {Type: "TEXT"},
		"status":      {Type: "TEXT"},
		"directories": {Type: "TEXT"},
		"mount_point": {Type: "TEXT"},
	}
	for name, want := range expected {
		actual, exists := columns[name]
		if !exists {
			return fmt.Errorf("required legacy o_connections column %s is missing", name)
		}
		if !strings.EqualFold(actual.Type, want.Type) || actual.NotNull != 0 || actual.PrimaryKey != want.PrimaryKey || actual.DefaultValue != nil {
			return fmt.Errorf("incompatible legacy o_connections column %s", name)
		}
	}
	return nil
}

func verifyLegacyConnectionRowID(database *gorm.DB) error {
	var indexes []sqliteIndexListEntry
	if err := database.Raw("PRAGMA index_list('o_connections')").Scan(&indexes).Error; err != nil {
		return fmt.Errorf("inspect legacy o_connections primary key: %w", err)
	}
	for _, index := range indexes {
		if index.Origin == "pk" {
			return errors.New("o_connections id is not the required SQLite rowid alias")
		}
	}
	return nil
}

func verifySMBCredentialSchema(database *gorm.DB) error {
	var connectionColumns []sqliteTableColumn
	if err := database.Raw("PRAGMA table_info('o_connections')").Scan(&connectionColumns).Error; err != nil {
		return fmt.Errorf("inspect o_connections: %w", err)
	}
	expectedConnectionColumns := map[string]sqliteTableColumn{
		"boot_id":           {Type: "TEXT"},
		"mount_ids":         {Type: "TEXT"},
		"credential_id":     {Type: "TEXT"},
		"credential_format": {Type: "TEXT"},
		"password_envelope": {Type: "BLOB"},
		"row_revision":      {Type: "INTEGER", NotNull: 1},
	}
	foundConnectionColumns := make(map[string]struct{}, len(expectedConnectionColumns))
	for _, column := range connectionColumns {
		expected, relevant := expectedConnectionColumns[column.Name]
		if !relevant {
			continue
		}
		if _, duplicate := foundConnectionColumns[column.Name]; duplicate {
			return fmt.Errorf("duplicate o_connections column %s", column.Name)
		}
		foundConnectionColumns[column.Name] = struct{}{}
		if !strings.EqualFold(column.Type, expected.Type) || column.NotNull != expected.NotNull || column.PrimaryKey != 0 {
			return fmt.Errorf("incompatible o_connections column %s", column.Name)
		}
		if column.Name == "row_revision" {
			if column.DefaultValue == nil || *column.DefaultValue != "0" {
				return errors.New("incompatible o_connections row_revision default")
			}
		} else if column.DefaultValue != nil {
			return fmt.Errorf("unexpected default for o_connections column %s", column.Name)
		}
	}
	if len(foundConnectionColumns) != len(expectedConnectionColumns) {
		return errors.New("o_connections SMB runtime columns are incomplete")
	}

	if err := verifySecurityMigrationsTable(database); err != nil {
		return err
	}
	return verifyCredentialIDIndex(database)
}

// verifyLegacyOnlySMBCredentialState is the downgrade/partial-deployment gate
// for this expand-only, write-contained release. Mutations are limited to
// legacy rows, but the runtime still reads plaintext passwords and loads no
// keyring. Sealed or migration-marked state must therefore fail before service
// construction. The cutover release must replace this gate atomically with its
// complete legacy/sealed classifier before it writes the first envelope.
func verifyLegacyOnlySMBCredentialState(database *gorm.DB) error {
	var nonLegacyRows int64
	if err := database.Raw(`SELECT count(*) FROM o_connections WHERE NOT ` +
		model2.LegacySMBCredentialRowPredicateSQL).Scan(&nonLegacyRows).Error; err != nil {
		return fmt.Errorf("classify o_connections rows: %w", err)
	}
	if nonLegacyRows != 0 {
		return errors.New("sealed or partially migrated SMB credential rows require the cutover-capable service")
	}

	var markers int64
	if err := database.Model(&model2.SecurityMigrationDBModel{}).Count(&markers).Error; err != nil {
		return fmt.Errorf("count security migration markers: %w", err)
	}
	if markers != 0 {
		return errors.New("security migration markers require the cutover-capable service")
	}
	return nil
}

func verifySecurityMigrationsTable(database *gorm.DB) error {
	var storedSQL string
	result := database.Raw(
		"SELECT sql FROM sqlite_master WHERE type = ? AND name = ?",
		"table",
		(&model2.SecurityMigrationDBModel{}).TableName(),
	).Scan(&storedSQL)
	if result.Error != nil {
		return fmt.Errorf("inspect security migration table SQL: %w", result.Error)
	}
	if result.RowsAffected != 1 || normalizeSQLiteSQL(storedSQL) != normalizeSQLiteSQL(securityMigrationsTableSQL) {
		return errors.New("incompatible security migration table definition")
	}

	var columns []sqliteTableColumn
	if err := database.Raw("PRAGMA table_info('o_security_migrations')").Scan(&columns).Error; err != nil {
		return fmt.Errorf("inspect security migration table columns: %w", err)
	}
	expected := []sqliteTableColumn{
		{Name: "name", Type: "TEXT", NotNull: 1, PrimaryKey: 1},
		{Name: "state", Type: "TEXT", NotNull: 1},
		{Name: "updated", Type: "INTEGER", NotNull: 1},
	}
	if len(columns) != len(expected) {
		return errors.New("incompatible security migration table columns")
	}
	for index := range expected {
		actual := columns[index]
		want := expected[index]
		if actual.Name != want.Name || !strings.EqualFold(actual.Type, want.Type) || actual.NotNull != want.NotNull || actual.PrimaryKey != want.PrimaryKey || actual.DefaultValue != nil {
			return fmt.Errorf("incompatible security migration column %s", want.Name)
		}
	}
	return nil
}

func verifyCredentialIDIndex(database *gorm.DB) error {
	var entries []sqliteIndexListEntry
	if err := database.Raw("PRAGMA index_list('o_connections')").Scan(&entries).Error; err != nil {
		return fmt.Errorf("inspect o_connections indexes: %w", err)
	}
	found := 0
	for _, entry := range entries {
		if entry.Name != smbCredentialIDIndexName {
			continue
		}
		found++
		if entry.Unique != 1 || entry.Partial != 1 || entry.Origin != "c" {
			return errors.New("incompatible SMB credential identity index flags")
		}
	}
	if found != 1 {
		return errors.New("SMB credential identity index is missing or duplicated")
	}

	var columns []sqliteIndexColumn
	if err := database.Raw("PRAGMA index_info('ux_o_connections_credential_id')").Scan(&columns).Error; err != nil {
		return fmt.Errorf("inspect SMB credential identity index columns: %w", err)
	}
	if len(columns) != 1 || columns[0].Sequence != 0 || columns[0].Name != "credential_id" || columns[0].CID < 0 {
		return errors.New("incompatible SMB credential identity index columns")
	}

	var storedSQL string
	result := database.Raw(
		"SELECT sql FROM sqlite_master WHERE type = ? AND name = ?",
		"index",
		smbCredentialIDIndexName,
	).Scan(&storedSQL)
	if result.Error != nil {
		return fmt.Errorf("inspect SMB credential identity index SQL: %w", result.Error)
	}
	if result.RowsAffected != 1 || normalizeSQLiteSQL(storedSQL) != normalizeSQLiteSQL(credentialIDIndexSQL) {
		return errors.New("incompatible SMB credential identity index definition")
	}
	return nil
}

func normalizeSQLiteSQL(statement string) string {
	// Preserve case because quoted CHECK literals are case-sensitive. This is
	// whitespace normalization for our pinned DDL, not a general SQL parser.
	return strings.Join(strings.Fields(statement), " ")
}
