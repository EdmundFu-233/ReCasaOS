//go:build linux

package service

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeAccountTools puts getent, useradd, userdel and smbpasswd on PATH,
// backed by a passwd file in a temporary directory. smbpasswd records its
// arguments and standard input, and fails when the file "smbpasswd.fail"
// exists. Returns the directory.
func fakeAccountTools(t *testing.T, passwd string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), mode); err != nil {
			t.Fatal(err)
		}
	}
	write("passwd", passwd, 0o600)
	write("getent", `#!/bin/sh
db="$(dirname "$0")/passwd"
[ "$1" = passwd ] || exit 1
if [ -z "$2" ]; then cat "$db"; exit 0; fi
grep "^$2:" "$db" || exit 2
`, 0o755)
	// useradd --system --no-create-home --shell S --comment C NAME
	write("useradd", `#!/bin/sh
db="$(dirname "$0")/passwd"
shell=""; comment=""
while [ $# -gt 1 ]; do
  case "$1" in --shell) shell="$2"; shift;; --comment) comment="$2"; shift;; esac
  shift
done
echo "$1:x:990:990:$comment:/:$shell" >> "$db"
`, 0o755)
	write("userdel", `#!/bin/sh
db="$(dirname "$0")/passwd"
grep -v "^$1:" "$db" > "$db.new"; mv "$db.new" "$db"
`, 0o755)
	write("smbpasswd", `#!/bin/sh
dir="$(dirname "$0")"
printf '%s\n' "$*" >> "$dir/smbpasswd.args"
cat >> "$dir/smbpasswd.stdin"
[ -e "$dir/smbpasswd.fail" ] && { echo "smbpasswd: failed" >&2; exit 1; }
exit 0
`, 0o755)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	nologin := filepath.Join(dir, "nologin")
	write("nologin", "#!/bin/sh\nexit 1\n", 0o755)
	previous := sambaNologinCandidates
	sambaNologinCandidates = []string{nologin}
	t.Cleanup(func() { sambaNologinCandidates = previous })
	return dir
}

func readFakeFile(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return string(data)
}

const systemPasswd = "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n"

func TestCreateSambaUserMakesANoLoginShareAccount(t *testing.T) {
	dir := fakeAccountTools(t, systemPasswd)
	if err := CreateSambaUser("alice", "s3cret pass"); err != nil {
		t.Fatalf("CreateSambaUser() error = %v", err)
	}
	passwd := readFakeFile(t, dir, "passwd")
	if !strings.Contains(passwd, "alice:x:990:990:"+sambaAccountComment+":/:"+filepath.Join(dir, "nologin")) {
		t.Fatalf("passwd = %q", passwd)
	}
	if args := readFakeFile(t, dir, "smbpasswd.args"); args != "-s -a alice\n" {
		t.Fatalf("smbpasswd args = %q: the password must not be an argument", args)
	}
	if stdin := readFakeFile(t, dir, "smbpasswd.stdin"); stdin != "s3cret pass\ns3cret pass\n" {
		t.Fatalf("smbpasswd stdin = %q", stdin)
	}
	users, err := ListSambaUsers()
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0] != "alice" {
		t.Fatalf("ListSambaUsers() = %v, want only the share account (not root, not nobody)", users)
	}
}

func TestCreateSambaUserRemovesTheAccountWhenSambaFails(t *testing.T) {
	dir := fakeAccountTools(t, systemPasswd)
	if err := os.WriteFile(filepath.Join(dir, "smbpasswd.fail"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CreateSambaUser("alice", "pw"); err == nil {
		t.Fatal("CreateSambaUser() succeeded although smbpasswd failed")
	}
	if strings.Contains(readFakeFile(t, dir, "passwd"), "alice:") {
		t.Fatal("a system account was left behind that Samba never learned about")
	}
}

func TestCreateSambaUserRejects(t *testing.T) {
	fakeAccountTools(t, systemPasswd)
	for name, tc := range map[string]struct {
		username, password string
		want               error
	}{
		"existing account":   {"root", "pw", ErrSambaUserExists},
		"uppercase":          {"Alice", "pw", ErrSambaUsernameInvalid},
		"config injection":   {"a\nforce user = root", "pw", ErrSambaUsernameInvalid},
		"leading digit":      {"1alice", "pw", ErrSambaUsernameInvalid},
		"too long":           {strings.Repeat("a", 32), "pw", ErrSambaUsernameInvalid},
		"empty password":     {"alice", "", ErrSambaPasswordEmpty},
		"multiline password": {"alice", "pw\nother", ErrSambaPasswordInvalid},
	} {
		if err := CreateSambaUser(tc.username, tc.password); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
}

// Only accounts created here may be re-keyed or removed: never root, never an
// unrelated nologin account.
func TestSystemAccountsAreNotManageable(t *testing.T) {
	dir := fakeAccountTools(t, systemPasswd)
	for _, name := range []string{"root", "nobody"} {
		if err := SetSambaPassword(name, "pw"); !errors.Is(err, ErrSambaUserNotManaged) {
			t.Errorf("SetSambaPassword(%s) err = %v", name, err)
		}
		if err := DeleteSambaUser(name); !errors.Is(err, ErrSambaUserNotManaged) {
			t.Errorf("DeleteSambaUser(%s) err = %v", name, err)
		}
		if managed, err := IsSambaShareAccount(name); err != nil || managed {
			t.Errorf("IsSambaShareAccount(%s) = %v, %v", name, managed, err)
		}
	}
	if readFakeFile(t, dir, "smbpasswd.args") != "" {
		t.Fatal("smbpasswd ran for a system account")
	}
	if readFakeFile(t, dir, "passwd") != systemPasswd {
		t.Fatal("system accounts changed")
	}
}

func TestDeleteSambaUser(t *testing.T) {
	dir := fakeAccountTools(t, systemPasswd)
	if err := CreateSambaUser("alice", "pw"); err != nil {
		t.Fatal(err)
	}
	if err := DeleteSambaUser("alice"); err != nil {
		t.Fatalf("DeleteSambaUser() error = %v", err)
	}
	if strings.Contains(readFakeFile(t, dir, "passwd"), "alice:") {
		t.Fatal("account still present")
	}
	if !strings.Contains(readFakeFile(t, dir, "smbpasswd.args"), "-x alice") {
		t.Fatal("not removed from Samba")
	}
	if err := DeleteSambaUser("alice"); err != nil {
		t.Fatalf("deleting a missing account: %v", err)
	}
}

func TestSetSambaPasswordRekeysAShareAccount(t *testing.T) {
	dir := fakeAccountTools(t, systemPasswd)
	if err := CreateSambaUser("alice", "old"); err != nil {
		t.Fatal(err)
	}
	if err := SetSambaPassword("alice", "new"); err != nil {
		t.Fatalf("SetSambaPassword() error = %v", err)
	}
	if !strings.HasSuffix(readFakeFile(t, dir, "smbpasswd.stdin"), "new\nnew\n") {
		t.Fatal("new password not written to smbpasswd")
	}
}
