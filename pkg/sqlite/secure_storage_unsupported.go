//go:build !linux

package sqlite

import (
	"errors"
	"os"
)

func prepareSecureDatabaseDirectory(string) (*os.File, error) {
	return nil, errors.New("secure SQLite storage requires Linux")
}

func secureDatabaseArtifacts(*os.File, bool) error {
	return errors.New("secure SQLite storage requires Linux")
}

func verifyDatabaseDirectoryPath(*os.File, string) error {
	return errors.New("secure SQLite storage requires Linux")
}

func databasePathForDirectory(string) string { return "" }
