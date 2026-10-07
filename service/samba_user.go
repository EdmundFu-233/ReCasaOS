package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/IceWhaleTech/CasaOS/pkg/filesecurity"
)

// Share accounts: system accounts that exist only to mount Samba shares. They
// are separate from the CasaOS login, have no home directory and no login
// shell, and are created, re-keyed and removed through the API.
//
// Ported from the ReCasaOS distribution (ReCasaOS/CasaOS, "let a share be
// restricted to a dedicated account", by Gary), adapted to this fork: every
// share here is already authenticated, so an account restricts a share
// instead of converting it from guest access.

const (
	// sambaAccountComment is written to the GECOS field and is how these
	// accounts are recognised later. It gates password changes and deletion:
	// matching too broadly would let the API re-key or remove a real account
	// of the machine, so the check fails towards leaving a stale account.
	sambaAccountComment = "CasaOS share account"

	sambaAccountToolTimeout = 30 * time.Second
)

var (
	// sambaUsernamePattern is deliberately narrower than what useradd accepts:
	// these names reach useradd, smbpasswd and smb.conf "valid users" and
	// "force user" lines, so anything outside a conservative POSIX set is
	// rejected rather than escaped.
	sambaUsernamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)

	// sambaNologinCandidates are the usual places of nologin(8); the first that
	// exists becomes the accounts' shell. A path that moves on every update
	// (a package store) is no good as a login shell, hence a list of stable
	// locations before a PATH lookup. /run/current-system/sw/bin is NixOS's.
	sambaNologinCandidates = []string{"/usr/sbin/nologin", "/sbin/nologin", "/usr/bin/nologin", "/run/current-system/sw/bin/nologin"}

	ErrSambaUsernameInvalid = errors.New("a share account name must be 1 to 31 characters, start with a lowercase letter or underscore, and contain only lowercase letters, digits, underscores and hyphens")
	ErrSambaPasswordEmpty   = errors.New("a share account password cannot be empty")
	ErrSambaPasswordInvalid = errors.New("a share account password cannot contain line breaks or NUL")
	ErrSambaUserExists      = errors.New("a system account with that name already exists")
	ErrSambaUserNotManaged  = errors.New("that account is not a CasaOS share account")
	ErrSambaNologinMissing  = errors.New("no nologin shell found for share accounts")
)

// ValidateSambaUsername reports whether name is safe to pass to the account
// tooling and into smb.conf. Callers must run it before anything else touches
// the name.
func ValidateSambaUsername(name string) error {
	if !sambaUsernamePattern.MatchString(name) {
		return ErrSambaUsernameInvalid
	}
	return nil
}

func validateSambaPassword(password string) error {
	if password == "" {
		return ErrSambaPasswordEmpty
	}
	// smbpasswd -s reads it line by line from standard input
	if strings.ContainsAny(password, "\r\n\x00") {
		return ErrSambaPasswordInvalid
	}
	return nil
}

func sambaNologinShell() (string, error) {
	for _, candidate := range sambaNologinCandidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	if path, err := exec.LookPath("nologin"); err == nil {
		return path, nil
	}
	return "", ErrSambaNologinMissing
}

// runAccountTool runs one of the account tools, resolved through PATH, with a
// deadline and bounded output. stdin, if any, never appears on a command line.
func runAccountTool(stdin string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sambaAccountToolTimeout)
	defer cancel()
	output := &boundedCommandOutput{limit: 8 << 10}
	command := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		command.Stdin = strings.NewReader(stdin)
	}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return output.buffer.Bytes(), fmt.Errorf("%s timed out", name)
	}
	return output.buffer.Bytes(), err
}

// sambaPasswdEntry looks an account up through NSS (getent), so the answer is
// the one useradd, smbd and the kernel's view agree on.
func sambaPasswdEntry(username string) ([]string, bool, error) {
	output, err := runAccountTool("", "getent", "passwd", username)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 2 { // getent: key not found
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("look up account: %w", err)
	}
	fields := strings.Split(strings.TrimSpace(string(output)), ":")
	if len(fields) < 7 || fields[0] != username {
		return nil, false, errors.New("look up account: malformed passwd entry")
	}
	return fields, true, nil
}

func isSambaShareAccountEntry(fields []string) bool {
	return len(fields) >= 7 && fields[4] == sambaAccountComment && filepath.Base(fields[6]) == "nologin"
}

// IsSambaShareAccount reports whether username is a share account created
// here.
func IsSambaShareAccount(username string) (bool, error) {
	if err := ValidateSambaUsername(username); err != nil {
		return false, err
	}
	fields, found, err := sambaPasswdEntry(username)
	if err != nil || !found {
		return false, err
	}
	return isSambaShareAccountEntry(fields), nil
}

// ListSambaUsers returns the share accounts created here, and no other account
// of the machine.
func ListSambaUsers() ([]string, error) {
	output, err := runAccountTool("", "getent", "passwd")
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	names := []string{}
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		fields := strings.Split(strings.TrimSpace(scanner.Text()), ":")
		if isSambaShareAccountEntry(fields) && sambaUsernamePattern.MatchString(fields[0]) {
			names = append(names, fields[0])
		}
	}
	return names, scanner.Err()
}

// CreateSambaUser adds a system account that can only be used for file
// sharing, then registers it with Samba. It gets no home directory and no
// login shell; the password goes to smbpasswd's standard input, never into
// the process table.
func CreateSambaUser(username, password string) error {
	if err := ValidateSambaUsername(username); err != nil {
		return err
	}
	if err := validateSambaPassword(password); err != nil {
		return err
	}
	if _, found, err := sambaPasswdEntry(username); err != nil {
		return err
	} else if found {
		return ErrSambaUserExists
	}
	shell, err := sambaNologinShell()
	if err != nil {
		return err
	}
	if output, err := runAccountTool("", "useradd", "--system", "--no-create-home", "--shell", shell, "--comment", sambaAccountComment, username); err != nil {
		return fmt.Errorf("create the system account: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if err := SetSambaPassword(username, password); err != nil {
		// do not leave a system account behind that Samba never learned about
		if output, delErr := runAccountTool("", "userdel", username); delErr != nil {
			return errors.Join(err, fmt.Errorf("remove the half-created account: %w: %s", delErr, strings.TrimSpace(string(output))))
		}
		return err
	}
	return nil
}

// SetSambaPassword sets or replaces the Samba password of a share account.
// It refuses any other account: without that, the endpoint would enrol root,
// or any system account, into Samba with a password the caller chose.
func SetSambaPassword(username, password string) error {
	if err := validateSambaPassword(password); err != nil {
		return err
	}
	managed, err := IsSambaShareAccount(username)
	if err != nil {
		return err
	}
	if !managed {
		return ErrSambaUserNotManaged
	}
	// -s: read the password twice from stdin; -a: no-op for a known account
	if output, err := runAccountTool(password+"\n"+password+"\n", "smbpasswd", "-s", "-a", username); err != nil {
		// the output can echo the account name, never the password
		return fmt.Errorf("set the share password: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// DeleteSambaUser removes a share account from Samba and from the system. It
// refuses any account not created here. Whether a share still names it is the
// caller's check (see the route).
func DeleteSambaUser(username string) error {
	if err := ValidateSambaUsername(username); err != nil {
		return err
	}
	fields, found, err := sambaPasswdEntry(username)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if !isSambaShareAccountEntry(fields) {
		return ErrSambaUserNotManaged
	}
	if output, err := runAccountTool("", "smbpasswd", "-x", username); err != nil {
		return fmt.Errorf("remove the Samba account: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if output, err := runAccountTool("", "userdel", username); err != nil {
		return fmt.Errorf("remove the system account: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

// setShareDirectoryOwner hands the top directory of a share to its account
// (account:account, 0770) or, with an empty username, back to root (0755).
// Without it the directory stays root-owned while the Samba session runs as
// the account (force user): the share authenticates and then refuses every
// write. Only the top directory changes, through the pinned management roots;
// the returned function restores the previous owner and mode.
func setShareDirectoryOwner(roots *filesecurity.ManagedRoots, path, username string) (func() error, error) {
	uid, gid, mode := 0, 0, os.FileMode(0o755)
	if username != "" {
		fields, found, err := sambaPasswdEntry(username)
		if err != nil {
			return nil, err
		}
		if !found || !isSambaShareAccountEntry(fields) {
			return nil, ErrSambaUserNotManaged
		}
		if uid, err = strconv.Atoi(fields[2]); err != nil {
			return nil, fmt.Errorf("account uid: %w", err)
		}
		if gid, err = strconv.Atoi(fields[3]); err != nil {
			return nil, fmt.Errorf("account gid: %w", err)
		}
		mode = 0o770
	}
	directory, err := roots.OpenDirectory(path)
	if err != nil {
		return nil, fmt.Errorf("open share directory: %w", err)
	}
	previous, err := directory.Stat()
	if err != nil {
		_ = directory.Close()
		return nil, fmt.Errorf("inspect share directory: %w", err)
	}
	stat, ok := previous.Sys().(*syscall.Stat_t)
	if !ok {
		_ = directory.Close()
		return nil, errors.New("inspect share directory: no ownership information")
	}
	restore := func() error {
		defer directory.Close()
		return errors.Join(directory.Chown(int(stat.Uid), int(stat.Gid)), directory.Chmod(previous.Mode().Perm()))
	}
	if err := errors.Join(directory.Chown(uid, gid), directory.Chmod(mode)); err != nil {
		return nil, errors.Join(fmt.Errorf("hand the share directory to %q: %w", username, err), restore())
	}
	return restore, nil
}
