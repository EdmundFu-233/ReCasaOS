package publicfiles

import (
	"context"
	"errors"
	"io"
)

var (
	errStorageCapacity = errors.New("public file storage worker capacity reached")
	errStorageTimeout  = errors.New("public file storage worker timed out")
	errStorageProtocol = errors.New("public file storage worker protocol failed")
)

// storageBackend is the only path from the long-lived HTTP portal into the
// configured share. Production uses disposable subprocesses; the direct
// secureRoot adapter exists only for focused filesystem tests.
type storageBackend interface {
	list(context.Context, string, int) ([]Entry, error)
	openRegular(context.Context, string) (storageFile, fileInfo, error)
	close() error
}

type storageFile interface {
	io.Reader
	io.Seeker
	io.Closer
}

// storageSourceError is implemented by the subprocess-backed file. A source
// failure after HTTP headers have been committed must abort the connection
// instead of allowing a truncated response to look successful.
type storageSourceError interface {
	sourceError() error
}
