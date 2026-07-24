//go:build !linux

package publicfiles

import (
	"crypto/sha256"
	"os"
)

type secureRoot struct{}

func openSecureRoot(string) (*secureRoot, error) {
	return nil, ErrUnsupported
}

func readVerifierFileSecure(string) ([sha256.Size]byte, error) {
	return [sha256.Size]byte{}, ErrUnsupported
}

func (r *secureRoot) close() error {
	return nil
}

func (r *secureRoot) list(string, int) ([]Entry, error) {
	return nil, ErrUnsupported
}

func (r *secureRoot) openRegular(string) (*os.File, fileInfo, error) {
	return nil, nil, ErrUnsupported
}

func isHiddenFilesystemError(error) bool {
	return false
}
