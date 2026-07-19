//go:build linux

package sqlite

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

var sqliteArtifactNames = []string{"casaOS.db", "casaOS.db-wal", "casaOS.db-shm", "casaOS.db-journal"}

func prepareSecureDatabaseDirectory(dbPath string) (*os.File, error) {
	if !filepath.IsAbs(dbPath) || filepath.Clean(dbPath) != dbPath || dbPath == string(filepath.Separator) {
		return nil, errors.New("database directory must be a clean absolute non-root path")
	}
	currentFD, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open filesystem root for database directory: %w", err)
	}
	components := strings.Split(strings.TrimPrefix(dbPath, string(filepath.Separator)), string(filepath.Separator))
	for index, component := range components {
		parentStickyWritable, validateErr := validateDatabaseDirectoryAncestor(currentFD)
		if validateErr != nil {
			_ = unix.Close(currentFD)
			return nil, fmt.Errorf("validate database directory ancestor before %q: %w", component, validateErr)
		}
		nextFD, openErr := unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) {
			if mkdirErr := unix.Mkdirat(currentFD, component, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(currentFD)
				return nil, fmt.Errorf("create database directory component: %w", mkdirErr)
			}
			nextFD, openErr = unix.Openat(currentFD, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(currentFD)
			return nil, fmt.Errorf("open database directory component: %w", openErr)
		}
		var childStat unix.Stat_t
		if err := unix.Fstat(nextFD, &childStat); err != nil {
			_ = unix.Close(currentFD)
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("inspect database directory component %q: %w", component, err)
		}
		serviceUID := uint32(os.Geteuid())
		if childStat.Mode&unix.S_IFMT != unix.S_IFDIR || childStat.Uid != 0 && childStat.Uid != serviceUID {
			_ = unix.Close(currentFD)
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("database directory component %q must be a real root/service-owned directory", component)
		}
		if parentStickyWritable && childStat.Uid != 0 && childStat.Uid != serviceUID {
			_ = unix.Close(currentFD)
			_ = unix.Close(nextFD)
			return nil, fmt.Errorf("database directory component %q is replaceable in a sticky ancestor", component)
		}
		if index == len(components)-1 && childStat.Uid != serviceUID {
			_ = unix.Close(currentFD)
			_ = unix.Close(nextFD)
			return nil, errors.New("database directory must be owned by the service user")
		}
		if err := unix.Close(currentFD); err != nil {
			_ = unix.Close(nextFD)
			return nil, err
		}
		currentFD = nextFD
	}
	directory := os.NewFile(uintptr(currentFD), dbPath)
	if directory == nil {
		_ = unix.Close(currentFD)
		return nil, errors.New("open database directory")
	}
	var directoryStat unix.Stat_t
	if err := unix.Fstat(currentFD, &directoryStat); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if directoryStat.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStat.Uid != uint32(os.Geteuid()) {
		_ = directory.Close()
		return nil, errors.New("database directory must be owned by the service user and be a real directory")
	}
	if err := unix.Fchmod(currentFD, 0o700); err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("secure database directory permissions: %w", err)
	}
	if err := verifyDatabaseDirectoryPath(directory, dbPath); err != nil {
		_ = directory.Close()
		return nil, err
	}
	if err := secureDatabaseArtifacts(directory, true); err != nil {
		_ = directory.Close()
		return nil, err
	}
	return directory, nil
}

func validateDatabaseDirectoryAncestor(directoryFD int) (bool, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(directoryFD, &stat); err != nil {
		return false, err
	}
	serviceUID := uint32(os.Geteuid())
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 && stat.Uid != serviceUID {
		return false, errors.New("ancestor must be a real root/service-owned directory")
	}
	writableByNonOwner := stat.Mode&0o022 != 0
	sticky := stat.Mode&unix.S_ISVTX != 0
	if writableByNonOwner && !sticky {
		return false, errors.New("ancestor is group/other writable without sticky rename protection")
	}
	return writableByNonOwner && sticky, nil
}

func verifyDatabaseDirectoryPath(directory *os.File, dbPath string) error {
	if directory == nil {
		return errors.New("database directory descriptor is nil")
	}
	pathInfo, err := os.Lstat(dbPath)
	if err != nil {
		return fmt.Errorf("inspect canonical database directory: %w", err)
	}
	openedInfo, err := directory.Stat()
	if err != nil {
		return fmt.Errorf("inspect pinned database directory: %w", err)
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(pathInfo, openedInfo) {
		return errors.New("canonical database directory no longer names the pinned directory")
	}
	// os.FileInfo.Sys exposes the standard library's syscall.Stat_t on Linux,
	// which is not type-identical to x/sys/unix.Stat_t on every toolchain.
	// Inspect the already pinned descriptor directly so the ownership check
	// cannot fail merely because those implementation types differ.
	var stat unix.Stat_t
	if err := unix.Fstat(int(directory.Fd()), &stat); err != nil {
		return fmt.Errorf("inspect pinned database directory metadata: %w", err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o777 != 0o700 {
		return errors.New("canonical database directory is not service-owned mode 0700")
	}
	return nil
}

func secureDatabaseArtifacts(directory *os.File, createMain bool) error {
	if directory == nil {
		return errors.New("database directory descriptor is nil")
	}
	for index, name := range sqliteArtifactNames {
		mustExist := index == 0 && createMain
		if err := secureDatabaseArtifact(int(directory.Fd()), name, mustExist); err != nil {
			return err
		}
	}
	if err := unix.Fsync(int(directory.Fd())); err != nil {
		return fmt.Errorf("sync secure SQLite directory: %w", err)
	}
	return nil
}

func secureDatabaseArtifact(directoryFD int, name string, create bool) error {
	var pathStat unix.Stat_t
	err := unix.Fstatat(directoryFD, name, &pathStat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) && create {
		createdFD, createErr := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if createErr == nil {
			if chmodErr := unix.Fchmod(createdFD, 0o600); chmodErr != nil {
				_ = unix.Close(createdFD)
				return chmodErr
			}
			if syncErr := unix.Fsync(createdFD); syncErr != nil {
				_ = unix.Close(createdFD)
				return syncErr
			}
			if closeErr := unix.Close(createdFD); closeErr != nil {
				return closeErr
			}
			if err := unix.Fsync(directoryFD); err != nil {
				return err
			}
			err = unix.Fstatat(directoryFD, name, &pathStat, unix.AT_SYMLINK_NOFOLLOW)
		} else if errors.Is(createErr, unix.EEXIST) {
			err = unix.Fstatat(directoryFD, name, &pathStat, unix.AT_SYMLINK_NOFOLLOW)
		} else {
			return fmt.Errorf("create secure SQLite artifact %s: %w", name, createErr)
		}
	}
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect SQLite artifact %s: %w", name, err)
	}
	if pathStat.Mode&unix.S_IFMT != unix.S_IFREG || pathStat.Nlink != 1 {
		return fmt.Errorf("SQLite artifact %s must be a single-link regular file", name)
	}
	openedFD, err := unix.Openat(directoryFD, name, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open SQLite artifact %s: %w", name, err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = unix.Close(openedFD)
		}
	}()
	var openedStat unix.Stat_t
	if err := unix.Fstat(openedFD, &openedStat); err != nil {
		return err
	}
	if openedStat.Dev != pathStat.Dev || openedStat.Ino != pathStat.Ino || openedStat.Mode&unix.S_IFMT != unix.S_IFREG || openedStat.Nlink != 1 || openedStat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("SQLite artifact %s changed while opening or is not service-owned", name)
	}
	if err := unix.Fchmod(openedFD, 0o600); err != nil {
		return fmt.Errorf("secure SQLite artifact %s permissions: %w", name, err)
	}
	if err := unix.Fsync(openedFD); err != nil {
		return fmt.Errorf("sync secure SQLite artifact %s: %w", name, err)
	}
	var finalPathStat unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &finalPathStat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("recheck SQLite artifact %s: %w", name, err)
	}
	if finalPathStat.Dev != openedStat.Dev || finalPathStat.Ino != openedStat.Ino || finalPathStat.Mode&unix.S_IFMT != unix.S_IFREG || finalPathStat.Nlink != 1 || finalPathStat.Uid != uint32(os.Geteuid()) || finalPathStat.Mode&0o777 != 0o600 {
		return fmt.Errorf("SQLite artifact %s changed while securing it", name)
	}
	if err := unix.Close(openedFD); err != nil {
		return fmt.Errorf("close secure SQLite artifact %s: %w", name, err)
	}
	closed = true
	return nil
}

func databasePathForDirectory(dbPath string) string {
	return filepath.Join(dbPath, "casaOS.db")
}
