package sqlite

import (
	"bytes"
	"strings"
	"testing"

	glebarezsqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestSecureSQLiteLoggerDoesNotInterpolatePasswordsOnError(t *testing.T) {
	type credential struct {
		ID       uint `gorm:"primaryKey"`
		Password string
	}
	var output bytes.Buffer
	database, err := gorm.Open(glebarezsqlite.Open(":memory:"), &gorm.Config{Logger: newSecureSQLiteLogger(&output)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.AutoMigrate(&credential{}); err != nil {
		t.Fatal(err)
	}
	const sentinel = "RECASAOS-SECRET-SENTINEL"
	if err := database.Create(&credential{ID: 1, Password: sentinel}).Error; err != nil {
		t.Fatal(err)
	}
	if err := database.Create(&credential{ID: 1, Password: sentinel}).Error; err == nil {
		t.Fatal("duplicate insert unexpectedly succeeded")
	}
	if strings.Contains(output.String(), sentinel) {
		t.Fatalf("SQLite error log leaked a password: %s", output.String())
	}
}
