package filesecurity

import (
	"errors"
	"sync"
)

const DefaultUploadReservedFreeBytes uint64 = 512 << 20

var (
	// ErrUploadSpaceUnavailable means the service could not prove the target
	// filesystem's available space. Upload admission must fail closed here.
	ErrUploadSpaceUnavailable = errors.New("upload filesystem space could not be verified")
	// ErrUploadSpaceInsufficient means the requested write would consume the
	// reserved system headroom or overlap another admitted write.
	ErrUploadSpaceInsufficient = errors.New("insufficient filesystem space for upload")
)

type UploadSpaceChecker func(*ManagedRoots, string) (uint64, error)

// UploadSpaceAdmission serializes the check-and-reserve portion of upload
// writes. The reservation covers only work currently being written; bytes
// already committed to staging remain accounted for by the next AvailableBytes
// read. Keeping the checker injectable makes the concurrency and fail-closed
// behavior deterministic without weakening the production descriptor path.
type UploadSpaceAdmission struct {
	mu       sync.Mutex
	checker  UploadSpaceChecker
	reserved uint64
}

func NewUploadSpaceAdmission(checker UploadSpaceChecker) *UploadSpaceAdmission {
	return &UploadSpaceAdmission{checker: checker}
}

func (a *UploadSpaceAdmission) Reserve(roots *ManagedRoots, parent string, bytes, reservedFree uint64) (func(), error) {
	if bytes == 0 {
		return func() {}, nil
	}
	if a == nil || a.checker == nil || roots == nil || parent == "" {
		return nil, ErrUploadSpaceUnavailable
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	available, err := a.checker(roots, parent)
	if err != nil {
		return nil, errors.Join(ErrUploadSpaceUnavailable, err)
	}
	if available < reservedFree || a.reserved > available-reservedFree || bytes > available-reservedFree-a.reserved {
		return nil, ErrUploadSpaceInsufficient
	}
	if bytes > ^uint64(0)-a.reserved {
		return nil, ErrUploadSpaceInsufficient
	}
	a.reserved += bytes

	var once sync.Once
	return func() {
		once.Do(func() {
			a.mu.Lock()
			if bytes <= a.reserved {
				a.reserved -= bytes
			} else {
				a.reserved = 0
			}
			a.mu.Unlock()
		})
	}, nil
}

var defaultUploadSpaceAdmission = NewUploadSpaceAdmission(func(roots *ManagedRoots, parent string) (uint64, error) {
	return roots.AvailableBytes(parent)
})

func ReserveUploadSpace(roots *ManagedRoots, parent string, bytes uint64) (func(), error) {
	return defaultUploadSpaceAdmission.Reserve(roots, parent, bytes, DefaultUploadReservedFreeBytes)
}
