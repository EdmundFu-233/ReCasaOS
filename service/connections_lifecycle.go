package service

import "sync"

var sambaConnectionLifecycleMu sync.Mutex

// AcquireSambaConnectionLifecycle serializes every in-process Samba
// connection mutation from its mount identity checks through the filesystem
// operation and corresponding database mutation.
func AcquireSambaConnectionLifecycle() func() {
	sambaConnectionLifecycleMu.Lock()
	return sambaConnectionLifecycleMu.Unlock
}
