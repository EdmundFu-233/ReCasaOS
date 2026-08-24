//go:build linux

package smbcredentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func writeTestCredential(t *testing.T, directory string, mode os.FileMode) []byte {
	t.Helper()
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x7a}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	defer keyring.Destroy()
	data, err := keyring.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, CredentialName)
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return data
}

func newCredentialDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func countCredentialDirectoryDescriptors(t *testing.T, directory string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	prefix := directory + string(filepath.Separator)
	count := 0
	for _, entry := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if target == directory || strings.HasPrefix(target, prefix) {
			count++
		}
	}
	return count
}

func TestLoadKeyringDirectoryAcceptsPinnedCanonicalCredential(t *testing.T) {
	directory := newCredentialDirectory(t)
	data := writeTestCredential(t, directory, 0o400)
	for _, mode := range []os.FileMode{0o700, 0o500} {
		if err := os.Chmod(directory, mode); err != nil {
			t.Fatal(err)
		}
		keyring, err := LoadKeyringDirectory(directory)
		if err != nil {
			t.Fatalf("mode %04o: %v", mode, err)
		}
		encoded, err := keyring.Marshal()
		keyring.Destroy()
		if err != nil || !bytes.Equal(encoded, data) {
			t.Fatalf("mode %04o loaded keyring mismatch: err=%v", mode, err)
		}
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CREDENTIALS_DIRECTORY", directory)
	fromEnvironment, err := LoadSystemdKeyring()
	if err != nil {
		t.Fatal(err)
	}
	fromEnvironment.Destroy()
}

func TestLoadKeyringDirectoryAcceptsMaximumCanonicalKeyring(t *testing.T) {
	directory := newCredentialDirectory(t)
	keyring, err := newKeyring(bytes.NewReader(bytes.Repeat([]byte{0x70}, keySize)))
	if err != nil {
		t.Fatal(err)
	}
	owned := []*Keyring{keyring}
	defer func() {
		for _, item := range owned {
			item.Destroy()
		}
	}()
	for index := 1; index < maxKeys; index++ {
		keyring, err = keyring.rotate(bytes.NewReader(bytes.Repeat([]byte{byte(0x70 + index)}, keySize)))
		if err != nil {
			t.Fatal(err)
		}
		owned = append(owned, keyring)
	}
	data, err := keyring.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(data)
	if len(data) != maxKeyringBytes {
		t.Fatalf("maximum keyring size=%d want=%d", len(data), maxKeyringBytes)
	}
	path := filepath.Join(directory, CredentialName)
	if err := os.WriteFile(path, data, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadKeyringDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()
	if len(loaded.KeyIDs()) != maxKeys || loaded.ActiveID() != keyring.ActiveID() {
		t.Fatalf("loaded maximum keyring: active=%q keys=%d", loaded.ActiveID(), len(loaded.KeyIDs()))
	}
}

func TestLoadSystemdKeyringRequiresCredentialDirectory(t *testing.T) {
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := LoadSystemdKeyring(); err == nil {
		t.Fatal("missing CREDENTIALS_DIRECTORY was accepted")
	}
}

func TestLoadSystemdKeyringAdmitsCanonicalCredentialForStartup(t *testing.T) {
	directory := newCredentialDirectory(t)
	data := writeTestCredential(t, directory, 0o400)
	t.Setenv(systemdCredentialsDirectoryEnvironment, directory)

	keyring, err := LoadSystemdKeyring()
	if err != nil || keyring == nil {
		t.Fatalf("configured admission keyring=%v err=%v", keyring, err)
	}
	encoded, marshalErr := keyring.Marshal()
	keyring.Destroy()
	defer clear(encoded)
	if marshalErr != nil || !bytes.Equal(encoded, data) {
		t.Fatalf("admitted keyring mismatch: err=%v", marshalErr)
	}
}

func TestLoadSystemdKeyringDoesNotLeakDescriptorsAcrossRepeatedAdmission(t *testing.T) {
	for name, data := range map[string][]byte{
		"valid":     nil,
		"malformed": []byte("malformed-ReCasaOS-SMB-keyring"),
	} {
		t.Run(name, func(t *testing.T) {
			directory := newCredentialDirectory(t)
			if data == nil {
				writeTestCredential(t, directory, 0o400)
			} else {
				credentialPath := filepath.Join(directory, CredentialName)
				if err := os.WriteFile(credentialPath, data, 0o400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(credentialPath, 0o400); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv(systemdCredentialsDirectoryEnvironment, directory)
			before := countCredentialDirectoryDescriptors(t, directory)
			for range 128 {
				keyring, err := LoadSystemdKeyring()
				if data == nil {
					if err != nil || keyring == nil {
						if keyring != nil {
							keyring.Destroy()
						}
						t.Fatalf("valid repeated admission keyring=%v err=%v", keyring, err)
					}
					keyring.Destroy()
				} else {
					if keyring != nil {
						keyring.Destroy()
					}
					if err == nil {
						t.Fatal("malformed repeated admission unexpectedly succeeded")
					}
				}
			}
			if after := countCredentialDirectoryDescriptors(t, directory); after != before {
				t.Fatalf("credential descriptor count=%d before=%d", after, before)
			}
		})
	}
}

func TestLoadKeyringDirectoryRejectsUnsafeObjectsWithoutBlocking(t *testing.T) {
	tests := map[string]func(*testing.T, string){
		"missing":   func(*testing.T, string) {},
		"mode 0440": func(t *testing.T, directory string) { writeTestCredential(t, directory, 0o440) },
		"mode 0600": func(t *testing.T, directory string) { writeTestCredential(t, directory, 0o600) },
		"mode 0644": func(t *testing.T, directory string) { writeTestCredential(t, directory, 0o644) },
		"setuid": func(t *testing.T, directory string) {
			writeTestCredential(t, directory, 0o400)
			if err := os.Chmod(filepath.Join(directory, CredentialName), 0o400|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		},
		"setgid": func(t *testing.T, directory string) {
			writeTestCredential(t, directory, 0o400)
			if err := os.Chmod(filepath.Join(directory, CredentialName), 0o400|os.ModeSetgid); err != nil {
				t.Fatal(err)
			}
		},
		"sticky": func(t *testing.T, directory string) {
			writeTestCredential(t, directory, 0o400)
			if err := os.Chmod(filepath.Join(directory, CredentialName), 0o400|os.ModeSticky); err != nil {
				t.Fatal(err)
			}
		},
		"symlink": func(t *testing.T, directory string) {
			target := filepath.Join(t.TempDir(), "target")
			if err := os.WriteFile(target, []byte("not a keyring"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, filepath.Join(directory, CredentialName)); err != nil {
				t.Fatal(err)
			}
		},
		"hardlink": func(t *testing.T, directory string) {
			writeTestCredential(t, directory, 0o400)
			if err := os.Link(filepath.Join(directory, CredentialName), filepath.Join(directory, "second-link")); err != nil {
				t.Fatal(err)
			}
		},
		"directory": func(t *testing.T, directory string) {
			if err := os.Mkdir(filepath.Join(directory, CredentialName), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"fifo": func(t *testing.T, directory string) {
			if err := unix.Mkfifo(filepath.Join(directory, CredentialName), 0o400); err != nil {
				t.Fatal(err)
			}
		},
		"oversized": func(t *testing.T, directory string) {
			if err := os.WriteFile(filepath.Join(directory, CredentialName), make([]byte, maxKeyringBytes+1), 0o400); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, prepare := range tests {
		t.Run(name, func(t *testing.T) {
			directory := newCredentialDirectory(t)
			prepare(t, directory)
			started := time.Now()
			keyring, err := LoadKeyringDirectory(directory)
			if keyring != nil {
				keyring.Destroy()
			}
			if err == nil {
				t.Fatal("unsafe credential object was accepted")
			}
			if elapsed := time.Since(started); elapsed > time.Second {
				t.Fatalf("unsafe credential load blocked for %s", elapsed)
			}
		})
	}
}

func TestLoadKeyringDirectoryRejectsUnsafeDirectoryAndNoncanonicalPaths(t *testing.T) {
	for name, mode := range map[string]os.FileMode{
		"0400":       0o400,
		"0600":       0o600,
		"0550":       0o550,
		"0505":       0o505,
		"0755":       0o755,
		"setuid":     0o500 | os.ModeSetuid,
		"setgid":     0o500 | os.ModeSetgid,
		"sticky bit": 0o500 | os.ModeSticky,
	} {
		t.Run("mode "+name, func(t *testing.T) {
			directory := newCredentialDirectory(t)
			writeTestCredential(t, directory, 0o400)
			if err := os.Chmod(directory, mode); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(directory, 0o700)
			if keyring, err := LoadKeyringDirectory(directory); err == nil {
				keyring.Destroy()
				t.Fatal("unsafe credential directory was accepted")
			}
		})
	}

	directory := newCredentialDirectory(t)
	writeTestCredential(t, directory, 0o400)
	unclean := directory + string(filepath.Separator) + ".." + string(filepath.Separator) + filepath.Base(directory)
	for _, path := range []string{"", ".", "/", unclean} {
		if keyring, err := LoadKeyringDirectory(path); err == nil {
			keyring.Destroy()
			t.Fatalf("noncanonical directory %q was accepted", path)
		}
	}

	target := newCredentialDirectory(t)
	writeTestCredential(t, target, 0o400)
	directoryLink := filepath.Join(t.TempDir(), "credential-directory-link")
	if err := os.Symlink(target, directoryLink); err != nil {
		t.Fatal(err)
	}
	if keyring, err := LoadKeyringDirectory(directoryLink); err == nil {
		keyring.Destroy()
		t.Fatal("symlinked credential directory was accepted")
	}
}

func TestLoadKeyringDirectoryRejectsMalformedCredentialWithoutEchoingIt(t *testing.T) {
	directory := newCredentialDirectory(t)
	secret := []byte("malformed-secret-keyring-sentinel")
	if err := os.WriteFile(filepath.Join(directory, CredentialName), secret, 0o400); err != nil {
		t.Fatal(err)
	}
	keyring, err := LoadKeyringDirectory(directory)
	if keyring != nil {
		keyring.Destroy()
	}
	if !errors.Is(err, ErrInvalidKeyring) || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatalf("malformed credential error = %v", err)
	}
}
