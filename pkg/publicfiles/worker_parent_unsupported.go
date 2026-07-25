//go:build !linux

package publicfiles

func newIsolatedStorage(string, string) (storageBackend, [32]byte, error) {
	return nil, [32]byte{}, ErrUnsupported
}
