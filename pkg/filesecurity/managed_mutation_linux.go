//go:build linux

package filesecurity

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/sys/unix"
)

// AcquireMutation serializes a caller-owned namespace transaction with every
// ManagedRoots content or namespace mutation. The returned release function is
// idempotent. mutationMu also precedes Close, so root descriptors remain pinned
// without holding m.mu.RLock for the lease lifetime. Callers may therefore use
// read-only ManagedRoots methods without recursively acquiring an RWMutex read
// lock while a writer is pending, but must not call another mutating method.
func (m *ManagedRoots) AcquireMutation() (func(), error) {
	if m == nil {
		return nil, ErrManagedPathOutsideRoots
	}
	m.mutationMu.Lock()
	m.mu.RLock()
	closed := m.closed
	m.mu.RUnlock()
	if closed {
		m.mutationMu.Unlock()
		return nil, fs.ErrClosed
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			m.mutationMu.Unlock()
		})
	}, nil
}

func (m *ManagedRoots) syncManagedDirectory(fd int, operation string, changed bool) error {
	syncDirectory := unix.Fsync
	if m.directorySync != nil {
		syncDirectory = m.directorySync
	}
	if err := syncDirectory(fd); err != nil {
		return &ManagedMutationError{
			Operation:         operation,
			Changed:           changed,
			DurabilityUnknown: true,
			Err:               err,
		}
	}
	return nil
}

func (m *ManagedRoots) unlinkManagedNameAndSync(parentFD int, name string, flags int, operation string, changed bool) error {
	if err := unix.Unlinkat(parentFD, name, flags); err != nil {
		return err
	}
	return m.syncManagedDirectory(parentFD, operation, changed)
}

// ManagedWritableFile keeps the global mutation lease until Close or Abort.
// The requested name is published atomically only by Close, after the file and
// its parent directory have been synchronized.
type ManagedWritableFile struct {
	roots           *ManagedRoots
	file            *os.File
	parentFD        int
	temporaryName   string
	destinationName string
	release         func()

	ioMu             sync.Mutex
	once             sync.Once
	result           error
	identity         ManagedFileIdentity
	identityCaptured bool
}

func (f *ManagedWritableFile) Write(data []byte) (int, error) {
	if f == nil {
		return 0, fs.ErrClosed
	}
	f.ioMu.Lock()
	defer f.ioMu.Unlock()
	if f.file == nil {
		return 0, fs.ErrClosed
	}
	return f.file.Write(data)
}

func (f *ManagedWritableFile) Sync() error {
	if f == nil {
		return fs.ErrClosed
	}
	f.ioMu.Lock()
	defer f.ioMu.Unlock()
	if f.file == nil {
		return fs.ErrClosed
	}
	return f.file.Sync()
}

// Close publishes the completed file. A post-rename directory-sync failure is
// returned as ManagedMutationError{Changed:true, DurabilityUnknown:true}.
func (f *ManagedWritableFile) Close() error {
	if f == nil {
		return fs.ErrClosed
	}
	f.once.Do(func() { f.result = f.finish(true) })
	return f.result
}

// PublishedIdentity returns the descriptor/name-bound identity captured after
// Close published the requested name and before the mutation lease was
// released. It remains available when Close reports a post-publication sync
// error so callers can retain a fail-closed idempotency record.
func (f *ManagedWritableFile) PublishedIdentity() (ManagedFileIdentity, error) {
	if f == nil {
		return ManagedFileIdentity{}, fs.ErrClosed
	}
	f.ioMu.Lock()
	defer f.ioMu.Unlock()
	if !f.identityCaptured {
		return ManagedFileIdentity{}, errors.New("managed file identity is unavailable")
	}
	return f.identity, nil
}

// Abort removes the unpublished staging inode and releases the mutation lease.
func (f *ManagedWritableFile) Abort() error {
	if f == nil {
		return nil
	}
	f.once.Do(func() { f.result = f.finish(false) })
	return f.result
}

func (f *ManagedWritableFile) finish(commit bool) (result error) {
	f.ioMu.Lock()
	defer f.ioMu.Unlock()
	published := false
	defer func() {
		if f.parentFD >= 0 {
			closeErr := unix.Close(f.parentFD)
			if published {
				closeErr = managedChangedMutationError("close published managed file parent", false, closeErr)
			}
			result = errors.Join(result, closeErr)
			f.parentFD = -1
		}
		if f.release != nil {
			f.release()
			f.release = nil
		}
	}()

	if f.file == nil {
		return fs.ErrClosed
	}
	if !commit {
		closeErr := f.file.Close()
		f.file = nil
		return errors.Join(closeErr, f.removeTemporary())
	}

	if err := f.file.Sync(); err != nil {
		closeErr := f.file.Close()
		f.file = nil
		return errors.Join(err, closeErr, f.removeTemporary())
	}
	if err := f.file.Close(); err != nil {
		f.file = nil
		return errors.Join(err, f.removeTemporary())
	}
	f.file = nil
	if err := unix.Renameat2(f.parentFD, f.temporaryName, f.parentFD, f.destinationName, unix.RENAME_NOREPLACE); err != nil {
		return errors.Join(classifyManagedResolutionError(err), f.removeTemporary())
	}
	published = true
	f.temporaryName = ""
	identity, err := captureManagedPublishedIdentity(f.parentFD, f.destinationName)
	if err != nil {
		return managedChangedMutationError("bind exclusively created file identity", true, err)
	}
	f.identity = identity
	f.identityCaptured = true
	return f.roots.syncManagedDirectory(f.parentFD, "sync exclusively created file parent", true)
}

func (f *ManagedWritableFile) removeTemporary() error {
	if f.temporaryName == "" {
		return nil
	}
	err := unix.Unlinkat(f.parentFD, f.temporaryName, 0)
	if errors.Is(err, unix.ENOENT) {
		f.temporaryName = ""
		return nil
	}
	if err != nil {
		return err
	}
	f.temporaryName = ""
	return f.roots.syncManagedDirectory(f.parentFD, "sync aborted managed file parent", false)
}

// CreateExclusive creates an unpublished destination-local staging inode and
// holds the mutation lease for the complete write lifetime. Close atomically
// publishes it without replacing an existing destination; Abort discards it.
func (m *ManagedRoots) CreateExclusive(absolutePath string, permission fs.FileMode) (*ManagedWritableFile, error) {
	if permission.Perm() == 0 || permission&^fs.ModePerm != 0 {
		return nil, fmt.Errorf("invalid managed file permissions")
	}
	release, err := m.AcquireMutation()
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			release()
		}
	}()

	root, location, err := m.resolveLocked(absolutePath)
	if err != nil {
		return nil, err
	}
	parentFD, destinationName, err := openManagedParent(root, location)
	if err != nil {
		return nil, err
	}
	parentLocation, err := m.matchLocked(filepath.Dir(location.Canonical))
	if err != nil {
		unix.Close(parentFD)
		return nil, err
	}
	if err := m.validateManagedDestinationFD(root, parentFD, parentLocation); err != nil {
		unix.Close(parentFD)
		return nil, err
	}
	var existing unix.Stat_t
	if err := unix.Fstatat(parentFD, destinationName, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		unix.Close(parentFD)
		return nil, fs.ErrExist
	} else if !errors.Is(err, unix.ENOENT) {
		unix.Close(parentFD)
		return nil, err
	}
	temporary, temporaryName, err := m.createManagedTemporary(parentFD, ".recasaos-create-")
	if err != nil {
		unix.Close(parentFD)
		return nil, err
	}
	if err := temporary.Chmod(permission.Perm()); err != nil {
		closeErr := temporary.Close()
		cleanupErr := m.unlinkManagedNameAndSync(parentFD, temporaryName, 0, "sync failed exclusive create cleanup", false)
		parentCloseErr := unix.Close(parentFD)
		return nil, errors.Join(err, closeErr, cleanupErr, parentCloseErr)
	}

	succeeded = true
	return &ManagedWritableFile{
		roots:           m,
		file:            temporary,
		parentFD:        parentFD,
		temporaryName:   temporaryName,
		destinationName: destinationName,
		release:         release,
	}, nil
}
