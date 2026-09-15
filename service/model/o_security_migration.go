package model

const (
	SMBCredentialMigrationName = "smb_credentials_v1"
	SecurityMigrationPending   = "pending"
	SecurityMigrationComplete  = "complete"
)

// SecurityMigrationDBModel records only durable, security-sensitive migration
// state. Merely creating the table or adding the SMB credential columns does
// not create a marker and does not claim that a cutover has happened.
type SecurityMigrationDBModel struct {
	Name    string `gorm:"column:name;type:text;primaryKey"`
	State   string `gorm:"column:state;type:text;not null"`
	Updated int64  `gorm:"column:updated;not null"`
}

func (*SecurityMigrationDBModel) TableName() string {
	return "o_security_migrations"
}
