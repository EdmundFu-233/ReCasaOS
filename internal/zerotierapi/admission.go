package zerotierapi

import "sync"

const zeroTierMaximumConcurrentPublicRequests = 4

var zeroTierPublicRequestSlots = make(chan struct{}, zeroTierMaximumConcurrentPublicRequests)

// TryAcquirePublicRequest bounds the browser-reachable work that may hold
// ZeroTier request or response buffers. The release function is idempotent so
// callers can safely defer it as soon as admission succeeds.
func TryAcquirePublicRequest() (release func(), ok bool) {
	select {
	case zeroTierPublicRequestSlots <- struct{}{}:
		var once sync.Once
		return func() {
			once.Do(func() {
				<-zeroTierPublicRequestSlots
			})
		}, true
	default:
		return nil, false
	}
}
