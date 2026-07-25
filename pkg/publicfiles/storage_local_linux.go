//go:build linux

package publicfiles

import "context"

type localStorageBackend struct {
	root *secureRoot
}

func newLocalStorageBackend(rootPath string) (*localStorageBackend, error) {
	root, err := openSecureRoot(rootPath)
	if err != nil {
		return nil, err
	}
	return &localStorageBackend{root: root}, nil
}

func (s *localStorageBackend) list(_ context.Context, relativePath string, maxEntries int) ([]Entry, error) {
	return s.root.list(relativePath, maxEntries)
}

func (s *localStorageBackend) openRegular(_ context.Context, relativePath string) (storageFile, fileInfo, error) {
	return s.root.openRegular(relativePath)
}

func (s *localStorageBackend) close() error {
	if s == nil || s.root == nil {
		return nil
	}
	return s.root.close()
}
