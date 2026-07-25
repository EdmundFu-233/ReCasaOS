//go:build !linux

package publicfiles

func newLocalStorageBackend(string) (storageBackend, error) {
	return nil, ErrUnsupported
}
