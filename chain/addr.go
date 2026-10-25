package chain

import (
	"math/rand/v2"
	"sync"
	"time"
)

// addrFailTTL is how long a candidate that failed to dial stays deprioritized.
// A var (not a const) so tests can shorten it.
var addrFailTTL = 30 * time.Second

// timeNow is replaceable in tests.
var timeNow = time.Now

// failedAddrs maps a "nodeAddr|candidate" key to the time of the last failure.
var failedAddrs sync.Map

func addrKey(nodeAddr, addr string) string {
	return nodeAddr + "|" + addr
}

// orderCandidates shuffles healthy candidates to the front and recently
// failed ones to the back, so a broken address does not get dialed first
// while the remaining ones keep sharing the load evenly.
func orderCandidates(nodeAddr string, addrs []string) []string {
	healthy := make([]string, 0, len(addrs))
	failed := make([]string, 0, len(addrs))

	now := timeNow()
	for _, addr := range addrs {
		key := addrKey(nodeAddr, addr)
		if v, ok := failedAddrs.Load(key); ok {
			if t, ok := v.(time.Time); ok && now.Sub(t) < addrFailTTL {
				failed = append(failed, addr)
				continue
			}
			failedAddrs.Delete(key)
		}
		healthy = append(healthy, addr)
	}

	rand.Shuffle(len(healthy), func(i, j int) { healthy[i], healthy[j] = healthy[j], healthy[i] })
	rand.Shuffle(len(failed), func(i, j int) { failed[i], failed[j] = failed[j], failed[i] })

	return append(healthy, failed...)
}

// markAddrFailed records that dialing addr failed for the given node.
func markAddrFailed(nodeAddr, addr string) {
	failedAddrs.Store(addrKey(nodeAddr, addr), timeNow())
}

// markAddrOK clears the failure record so the candidate rejoins the rotation.
func markAddrOK(nodeAddr, addr string) {
	failedAddrs.Delete(addrKey(nodeAddr, addr))
}
