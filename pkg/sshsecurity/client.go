// Package sshsecurity provides a host-key-verified client for the local SSH
// daemon. The CasaOS-Common helper uses InsecureIgnoreHostKey and must not be
// used with passwords.
package sshsecurity

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

const defaultHostKeyDirectory = "/etc/ssh"

func DialLocal(user, password, port string) (*ssh.Client, error) {
	callback, err := LoadHostKeyCallback(defaultHostKeyDirectory)
	if err != nil {
		return nil, fmt.Errorf("load local SSH host keys: %w", err)
	}
	configuration := &ssh.ClientConfig{
		Timeout:         5 * time.Second,
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: callback,
	}
	return ssh.Dial("tcp", net.JoinHostPort("127.0.0.1", port), configuration)
}

// LoadHostKeyCallback trusts only public host keys already protected by the
// local OS. It does not use ssh-keyscan or trust-on-first-use.
func LoadHostKeyCallback(directory string) (ssh.HostKeyCallback, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, errors.New("SSH host-key directory must be an absolute clean path")
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || !trustedFileMetadata(directoryInfo, false) {
		return nil, errors.New("SSH host-key directory is not trusted")
	}
	paths, err := filepath.Glob(filepath.Join(directory, "ssh_host_*_key.pub"))
	if err != nil {
		return nil, err
	}
	trusted := make([][]byte, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !trustedFileMetadata(info, true) {
			continue
		}
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		content, readErr := io.ReadAll(io.LimitReader(file, 16<<10))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil {
			continue
		}
		key, _, _, rest, err := ssh.ParseAuthorizedKey(content)
		if err != nil || len(strings.TrimSpace(string(rest))) != 0 {
			continue
		}
		trusted = append(trusted, append([]byte(nil), key.Marshal()...))
	}
	if len(trusted) == 0 {
		return nil, errors.New("no trusted local SSH host public keys found")
	}

	return func(_ string, _ net.Addr, presented ssh.PublicKey) error {
		if _, certificate := presented.(*ssh.Certificate); certificate {
			return errors.New("SSH host certificates require an explicitly configured CA")
		}
		encoded := presented.Marshal()
		for _, candidate := range trusted {
			if len(encoded) == len(candidate) && subtle.ConstantTimeCompare(encoded, candidate) == 1 {
				return nil
			}
		}
		return errors.New("local SSH host key does not match a protected system key")
	}, nil
}

func trustedFileMetadata(info os.FileInfo, requireSingleLink bool) bool {
	if info.Mode().Perm()&0o022 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (stat.Uid != 0 && stat.Uid != uint32(os.Geteuid())) {
		return false
	}
	return !requireSingleLink || stat.Nlink == 1
}
