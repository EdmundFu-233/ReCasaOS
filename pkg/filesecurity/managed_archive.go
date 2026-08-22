package filesecurity

import (
	"io"
	"os"
)

// ManagedArchiveVisitor receives one entry at a time from a descriptor-bound
// managed archive walk. relative is empty for the selected top-level entry and
// otherwise contains only validated child components. reader is non-nil only
// for a regular file and is valid only for the duration of the callback. Its
// dynamic type deliberately exposes neither Close nor Fd.
type ManagedArchiveVisitor func(relative string, depth int, info os.FileInfo, reader io.Reader) error
