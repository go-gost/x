package tun

import (
	"sync"

	ht "github.com/go-gost/x/handler/tun"
)

var (
	decMu sync.RWMutex
	decs  = map[string]ht.DecisionEvaluator{}
)

// RegisterDecisionEvaluator associates a DecisionEvaluator with a tun listener guid.
// This allows in-process callers (like Wing) to attach rich decision logic to the
// conn context created by the TUN listener.
func RegisterDecisionEvaluator(guid string, dec ht.DecisionEvaluator) {
	if guid == "" {
		return
	}
	decMu.Lock()
	decs[guid] = dec
	decMu.Unlock()
}

// UnregisterDecisionEvaluator removes the DecisionEvaluator associated with guid.
func UnregisterDecisionEvaluator(guid string) {
	if guid == "" {
		return
	}
	decMu.Lock()
	delete(decs, guid)
	decMu.Unlock()
}

func getDecisionEvaluator(guid string) ht.DecisionEvaluator {
	if guid == "" {
		return nil
	}
	decMu.RLock()
	dec := decs[guid]
	decMu.RUnlock()
	return dec
}
