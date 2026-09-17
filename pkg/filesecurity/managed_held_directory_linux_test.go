//go:build linux

package filesecurity

import (
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func openHeldDirectoryTestRoots(t *testing.T) (*ManagedRoots, string) {
	t.Helper()
	root := t.TempDir()
	roots, err := OpenManagementFileRoots([]string{root})
	if err != nil {
		t.Fatalf("open management roots: %v", err)
	}
	t.Cleanup(func() { _ = roots.Close() })
	return roots, root
}

func TestHeldDirectoryOperationsSurvivePathSwap(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	heldPath := filepath.Join(root, "held")
	if err := os.Mkdir(heldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := roots.OpenDirectory(heldPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	// Swap the pathname after the descriptor was pinned: the original inode
	// moves aside and a decoy directory takes the old path.
	originalHeld := heldPath + ".original"
	if err := os.Rename(heldPath, originalHeld); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(heldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(heldPath, "decoy"), []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}

	writer, err := roots.CreateExclusiveIn(directory, "chunk", 0o600)
	if err != nil {
		t.Fatalf("create through held directory: %v", err)
	}
	if _, err := writer.Write([]byte("data")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("publish through held directory: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(originalHeld, "chunk"))
	if err != nil || string(data) != "data" {
		t.Fatalf("held directory chunk = %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(heldPath, "chunk")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("decoy path received the chunk: %v", err)
	}

	opened, err := roots.OpenRegularIn(directory, "chunk")
	if err != nil {
		t.Fatalf("open through held directory: %v", err)
	}
	contents, readErr := io.ReadAll(opened)
	info, statErr := opened.Stat()
	closeErr := opened.Close()
	if readErr != nil || statErr != nil || closeErr != nil || string(contents) != "data" || info.Size() != 4 {
		t.Fatalf("opened held chunk = %q, %+v, %v, %v, %v", contents, info, readErr, statErr, closeErr)
	}

	if err := roots.RemoveIn(directory, "chunk"); err != nil {
		t.Fatalf("remove through held directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(originalHeld, "chunk")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("held chunk remained after removal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(heldPath, "decoy")); err != nil {
		t.Fatalf("decoy entry changed: %v", err)
	}
}

func TestRemoveHeldTreeRemovesOnlyTheHeldInode(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	parentPath := filepath.Join(root, "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(parentPath, "session")
	if err := os.MkdirAll(filepath.Join(sessionPath, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionPath, "1"), []byte("chunk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionPath, "nested", "2"), []byte("chunk"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := roots.OpenDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	held, err := roots.OpenDirectory(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := roots.RemoveHeldTree(parent, held, "session"); err != nil {
		t.Fatalf("remove held tree: %v", err)
	}
	entries, err := os.ReadDir(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("held tree removal left residue: %#v", entries)
	}
}

func TestRemoveHeldTreeFailsClosedOnNameReplacement(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	parentPath := filepath.Join(root, "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(parentPath, "session")
	if err := os.Mkdir(sessionPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionPath, "1"), []byte("chunk"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := roots.OpenDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	held, err := roots.OpenDirectory(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()

	if err := os.Rename(sessionPath, sessionPath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(sessionPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionPath, "decoy"), []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := roots.RemoveHeldTree(parent, held, "session"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("replaced name removal error = %v, want ErrUnsafePath", err)
	}
	decoy, err := os.ReadFile(filepath.Join(sessionPath, "decoy"))
	if err != nil || string(decoy) != "decoy" {
		t.Fatalf("replacement was deleted: %q, %v", decoy, err)
	}
	original, err := os.ReadFile(filepath.Join(sessionPath+".original", "1"))
	if err != nil || string(original) != "chunk" {
		t.Fatalf("held tree was deleted: %q, %v", original, err)
	}
}

func TestRemoveHeldTreeTreatsMissingNameAsRemoved(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	parentPath := filepath.Join(root, "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	sessionPath := filepath.Join(parentPath, "session")
	if err := os.Mkdir(sessionPath, 0o700); err != nil {
		t.Fatal(err)
	}
	parent, err := roots.OpenDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	held, err := roots.OpenDirectory(sessionPath)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := os.Remove(sessionPath); err != nil {
		t.Fatal(err)
	}
	if err := roots.RemoveHeldTree(parent, held, "session"); err != nil {
		t.Fatalf("missing name removal error = %v", err)
	}
}

func TestRemoveHeldTreeRejectsNonDirectoryDescriptors(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	parentPath := filepath.Join(root, "parent")
	if err := os.Mkdir(parentPath, 0o700); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(parentPath, "file")
	if err := os.WriteFile(filePath, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	parent, err := roots.OpenDirectory(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	opened, err := roots.OpenRegular(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if err := roots.RemoveHeldTree(parent, opened, "file"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("non-directory held descriptor error = %v, want ErrUnsafePath", err)
	}
	if err := roots.RemoveHeldTree(opened, parent, "file"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("non-directory parent descriptor error = %v, want ErrUnsafePath", err)
	}
}

func TestHeldDirectoryCommitSurvivesStagingPathSwap(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	stagingPath := filepath.Join(root, "staging")
	if err := os.Mkdir(stagingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := roots.OpenDirectory(stagingPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	payload := []byte("payload")
	writer, err := roots.CreateExclusiveIn(directory, ".complete", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	identity, err := writer.PublishedIdentity()
	if err != nil {
		t.Fatal(err)
	}

	// Swap the staging pathname and plant a replacement at the old path.
	if err := os.Rename(stagingPath, stagingPath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stagingPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stagingPath, ".complete"), []byte("evil"), 0o600); err != nil {
		t.Fatal(err)
	}

	target := filepath.Join(root, "target")
	if _, err := roots.CommitNoReplaceWithExpectedIdentityAndDigestIn(directory, ".complete", target, identity, sha256.Sum256(payload)); err != nil {
		t.Fatalf("commit from held directory: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != string(payload) {
		t.Fatalf("published target = %q, %v", data, err)
	}
	decoy, err := os.ReadFile(filepath.Join(stagingPath, ".complete"))
	if err != nil || string(decoy) != "evil" {
		t.Fatalf("decoy staging entry changed: %q, %v", decoy, err)
	}
}

func TestHeldDirectoryRejectsUnsafeNamesAndEntries(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	heldPath := filepath.Join(root, "held")
	if err := os.Mkdir(heldPath, 0o700); err != nil {
		t.Fatal(err)
	}
	directory, err := roots.OpenDirectory(heldPath)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()

	for _, name := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if _, err := roots.CreateExclusiveIn(directory, name, 0o600); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("CreateExclusiveIn(%q) error = %v, want ErrUnsafePath", name, err)
		}
		if _, err := roots.OpenRegularIn(directory, name); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("OpenRegularIn(%q) error = %v, want ErrUnsafePath", name, err)
		}
		if err := roots.RemoveIn(directory, name); !errors.Is(err, ErrUnsafePath) {
			t.Fatalf("RemoveIn(%q) error = %v, want ErrUnsafePath", name, err)
		}
	}

	writer, err := roots.CreateExclusiveIn(directory, "chunk", 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.CreateExclusiveIn(directory, "chunk", 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("second exclusive create error = %v, want fs.ErrExist", err)
	}

	if err := os.Mkdir(filepath.Join(heldPath, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := roots.RemoveIn(directory, "sub"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("RemoveIn(directory) error = %v, want ErrUnsafePath", err)
	}
	if _, err := roots.OpenRegularIn(directory, "sub"); err == nil {
		t.Fatal("OpenRegularIn accepted a directory")
	}
	if err := os.Symlink(filepath.Join(heldPath, "chunk"), filepath.Join(heldPath, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := roots.OpenRegularIn(directory, "link"); err == nil {
		t.Fatal("OpenRegularIn accepted a symlink")
	}
	if _, err := roots.CreateExclusiveIn(directory, "link", 0o600); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("CreateExclusiveIn over symlink error = %v, want fs.ErrExist", err)
	}
	if err := roots.RemoveIn(directory, "link"); err != nil {
		t.Fatalf("RemoveIn(symlink) error = %v", err)
	}
}

func TestHeldDirectoryCreationRejectsNonDirectoryDescriptor(t *testing.T) {
	roots, root := openHeldDirectoryTestRoots(t)
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened, err := roots.OpenRegular(file)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := roots.CreateExclusiveIn(opened, "chunk", 0o600); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("CreateExclusiveIn(file descriptor) error = %v, want ErrUnsafePath", err)
	}
	if _, err := roots.OpenRegularIn(opened, "chunk"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("OpenRegularIn(file descriptor) error = %v, want ErrUnsafePath", err)
	}
	if err := roots.RemoveIn(opened, "chunk"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("RemoveIn(file descriptor) error = %v, want ErrUnsafePath", err)
	}
}
