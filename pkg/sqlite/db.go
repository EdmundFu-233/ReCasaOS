/*
 * @Author: LinkLeong link@icewhale.com
 * @Date: 2022-05-13 18:15:46
 * @LastEditors: LinkLeong
 * @LastEditTime: 2022-08-31 13:39:24
 * @FilePath: /CasaOS/pkg/sqlite/db.go
 * @Description:
 * @Website: https://www.casaos.io
 * Copyright (c) 2022 by icewhale, All Rights Reserved.
 */
package sqlite

import (
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	model2 "github.com/IceWhaleTech/CasaOS/service/model"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var (
	gdb                    *gorm.DB
	databaseDirectory      *os.File
	databaseInitialization sync.Mutex
)

func GetDb(dbPath string) *gorm.DB {
	databaseInitialization.Lock()
	defer databaseInitialization.Unlock()

	if gdb != nil {
		return gdb
	}

	directory, err := prepareSecureDatabaseDirectory(dbPath)
	if err != nil {
		panic(fmt.Sprintf("secure SQLite storage initialization failed: %v", err))
	}
	failed := true
	defer func() {
		if failed {
			_ = directory.Close()
		}
	}()

	db, err := gorm.Open(sqlite.Open(databasePathForDirectory(dbPath)), &gorm.Config{Logger: newSecureSQLiteLogger(os.Stderr)})
	if err != nil {
		panic(fmt.Sprintf("SQLite connect failed: %v", err))
	}

	c, err := db.DB()
	if err != nil {
		panic(fmt.Sprintf("SQLite connection handle failed: %v", err))
	}
	defer func() {
		if failed {
			_ = c.Close()
		}
	}()
	c.SetMaxIdleConns(10)
	c.SetMaxOpenConns(1)
	c.SetConnMaxIdleTime(time.Second * 1000)
	if err := verifyDatabaseDirectoryPath(directory, dbPath); err != nil {
		panic(fmt.Sprintf("SQLite directory identity check failed: %v", err))
	}

	err = db.AutoMigrate(&model2.AppNotify{}, model2.SharesDBModel{}, model2.PeerDriveDBModel{})
	if err != nil {
		panic(fmt.Sprintf("SQLite schema migration failed: %v", err))
	}
	if err := expandSMBCredentialSchema(db); err != nil {
		panic(fmt.Sprintf("SQLite SMB credential schema expansion failed: %v", err))
	}

	for _, statement := range []string{
		"DROP TABLE IF EXISTS o_application",
		"DROP TABLE IF EXISTS o_friend",
		"DROP TABLE IF EXISTS o_person_download",
		"DROP TABLE IF EXISTS o_person_down_record",
	} {
		if result := db.Exec(statement); result.Error != nil {
			panic(fmt.Sprintf("SQLite legacy schema cleanup failed: %v", result.Error))
		}
	}
	if err := secureDatabaseArtifacts(directory, true); err != nil {
		panic(fmt.Sprintf("secure SQLite artifacts failed: %v", err))
	}
	if err := verifyDatabaseDirectoryPath(directory, dbPath); err != nil {
		panic(fmt.Sprintf("SQLite directory identity changed during initialization: %v", err))
	}

	// SQLite canonicalizes filenames before deriving journal/WAL paths, so the
	// descriptor is an identity witness rather than a pathname indirection. The
	// validated ancestor topology prevents non-owner rename/replacement; root and
	// the service UID remain inside the trusted-host boundary.
	databaseDirectory = directory
	gdb = db
	failed = false
	return db
}

func newSecureSQLiteLogger(output io.Writer) logger.Interface {
	return logger.New(log.New(output, "", log.LstdFlags), logger.Config{
		SlowThreshold:             2 * time.Second,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
		Colorful:                  false,
	})
}
