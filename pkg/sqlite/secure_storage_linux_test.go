//go:build linux

package sqlite

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	gormsqlite "github.com/glebarez/sqlite"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"
)

func TestPrepareSecureDatabaseDirectoryPreservesContentsAndSecuresArtifacts(t *testing.T) {
	databasePath := filepath.Join(secureSQLiteTestRoot(t), "database")
	if err := os.Mkdir(databasePath, 0o777); err != nil {
		t.Fatal(err)
	}
	expectedHashes := make(map[string][sha256.Size]byte, len(sqliteArtifactNames))
	for _, name := range sqliteArtifactNames {
		content := []byte("legacy-content-" + name)
		path := filepath.Join(databasePath, name)
		if err := os.WriteFile(path, content, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o666); err != nil {
			t.Fatal(err)
		}
		expectedHashes[name] = sha256.Sum256(content)
	}
	directory, err := prepareSecureDatabaseDirectory(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	assertMode(t, databasePath, 0o700)
	for _, name := range sqliteArtifactNames {
		path := filepath.Join(databasePath, name)
		assertMode(t, path, 0o600)
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(content) != expectedHashes[name] {
			t.Fatalf("%s content changed while securing permissions", name)
		}
		assertSQLiteArtifactMetadata(t, path)
	}
}

func TestPrepareSecureDatabaseDirectoryIgnoresPermissiveUmask(t *testing.T) {
	root := secureSQLiteTestRoot(t)
	oldUmask := unix.Umask(0)
	defer unix.Umask(oldUmask)
	databasePath := filepath.Join(root, "nested", "database")
	directory, err := prepareSecureDatabaseDirectory(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	assertMode(t, databasePath, 0o700)
	assertMode(t, filepath.Join(databasePath, "casaOS.db"), 0o600)
}

func TestPrepareSecureDatabaseDirectoryRejectsSymlinkDirectoryWithoutChangingTarget(t *testing.T) {
	root := secureSQLiteTestRoot(t)
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "database")); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSecureDatabaseDirectory(filepath.Join(root, "database")); err == nil {
		t.Fatal("symlink database directory unexpectedly accepted")
	}
	assertMode(t, target, 0o755)
}

func TestPrepareSecureDatabaseDirectoryRejectsSymlinkAndHardlinkedArtifacts(t *testing.T) {
	for _, useHardlink := range []bool{false, true} {
		t.Run(map[bool]string{false: "symlink", true: "hardlink"}[useHardlink], func(t *testing.T) {
			root := secureSQLiteTestRoot(t)
			databasePath := filepath.Join(root, "database")
			if err := os.Mkdir(databasePath, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(root, "precious")
			const content = "do-not-touch"
			if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			artifact := filepath.Join(databasePath, "casaOS.db")
			var err error
			if useHardlink {
				err = os.Link(target, artifact)
			} else {
				err = os.Symlink(target, artifact)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := prepareSecureDatabaseDirectory(databasePath); err == nil {
				t.Fatal("unsafe SQLite artifact unexpectedly accepted")
			}
			after, err := os.ReadFile(target)
			if err != nil || string(after) != content {
				t.Fatalf("external target changed: content=%q err=%v", after, err)
			}
			assertMode(t, target, 0o644)
		})
	}
}

func TestPrepareSecureDatabaseDirectoryRejectsReplaceableNonStickyAncestor(t *testing.T) {
	root := secureSQLiteTestRoot(t)
	replaceableParent := filepath.Join(root, "replaceable")
	databasePath := filepath.Join(replaceableParent, "database")
	if err := os.Mkdir(replaceableParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(replaceableParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSecureDatabaseDirectory(databasePath); err == nil {
		t.Fatal("database beneath a non-sticky group/other-writable ancestor was accepted")
	}
	// The rejected topology really is pathname-replaceable: the same operation
	// is available to any UID with write access to this non-sticky parent.
	movedPath := databasePath + ".moved"
	if err := os.Rename(databasePath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(databasePath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement directory was unexpectedly populated: entries=%v err=%v", entries, err)
	}
}

func TestPrepareSecureDatabaseDirectoryRejectsForeignOwnedChildInStickyAncestor(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root is required to create a foreign-owned sticky-parent fixture")
	}
	root := secureSQLiteTestRoot(t)
	stickyParent := filepath.Join(root, "sticky")
	databasePath := filepath.Join(stickyParent, "database")
	if err := os.Mkdir(stickyParent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stickyParent, os.ModeSticky|0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(databasePath, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareSecureDatabaseDirectory(databasePath); err == nil {
		t.Fatal("foreign-owned child in sticky writable ancestor was accepted")
	}
}

func TestDatabaseDirectoryIdentityDetectsRenameAndReplacement(t *testing.T) {
	databasePath := filepath.Join(secureSQLiteTestRoot(t), "database")
	directory, err := prepareSecureDatabaseDirectory(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	movedPath := databasePath + ".moved"
	if err := os.Rename(databasePath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(databasePath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := verifyDatabaseDirectoryPath(directory, databasePath); err == nil {
		t.Fatal("canonical pathname replacement matched the pinned directory")
	}
	entries, err := os.ReadDir(databasePath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("replacement directory received SQLite artifacts: entries=%v err=%v", entries, err)
	}
}

func TestSQLiteWALArtifactsRemainServiceOwnedSingleLinkMode0600(t *testing.T) {
	root := secureSQLiteTestRoot(t)
	oldUmask := unix.Umask(0)
	defer unix.Umask(oldUmask)
	databasePath := filepath.Join(root, "database")
	directory, err := prepareSecureDatabaseDirectory(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	database, err := gorm.Open(gormsqlite.Open(databasePathForDirectory(databasePath)), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDatabase, err := database.DB()
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDatabase.Close()
	if result := database.Exec("PRAGMA journal_mode=WAL"); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := database.Exec("CREATE TABLE secure_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL)"); result.Error != nil {
		t.Fatal(result.Error)
	}
	if result := database.Exec("INSERT INTO secure_probe(value) VALUES (?)", "sentinel"); result.Error != nil {
		t.Fatal(result.Error)
	}
	if err := verifyDatabaseDirectoryPath(directory, databasePath); err != nil {
		t.Fatal(err)
	}
	if err := secureDatabaseArtifacts(directory, true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"casaOS.db", "casaOS.db-wal", "casaOS.db-shm"} {
		assertSQLiteArtifactMetadata(t, filepath.Join(databasePath, name))
	}
}

func assertSQLiteArtifactMetadata(t *testing.T, path string) {
	t.Helper()
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		t.Fatal(err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || stat.Mode&0o777 != 0o600 {
		t.Fatalf("unsafe SQLite artifact metadata for %s: uid=%d nlink=%d mode=%o", path, stat.Uid, stat.Nlink, stat.Mode&0o777)
	}
}

func secureSQLiteTestRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	// testing.TempDir requests mode 0777 for its numbered child and relies on
	// the process umask. Make the fixture explicit so a permissive runner umask
	// does not accidentally construct a topology that production must reject.
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	assertMode(t, root, 0o700)
	return root
}

func assertMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if actual := info.Mode().Perm(); actual != expected {
		t.Fatalf("%s mode = %o, want %o", path, actual, expected)
	}
}
