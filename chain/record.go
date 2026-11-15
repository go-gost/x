package chain

import (
	"errors"
	"time"

	"github.com/go-gost/core/chain"
)

// ChainRecorded is the in-process hook invoked once per node dial that goes
// through a configured chain. The default is a no-op; the dashboard swaps it
// for its collector when it is enabled. Error classification:
//
//   "resolve"   — host resolution for the node failed, no dial was attempted
//   "dial"      — the node's own connector rejected/failed the dial
//   "handshake" — the node's transport handshake failed
//
// d is the elapsed time of the attempt; it is only meaningful (non-zero
// on average) for a successful call, but is always measured. err is the
// classified error for failures, nil on success.
var ChainRecorded = func(chainName string, hop int, node string, d time.Duration, err error) {}

var (
	errResolve   = errors.New("resolve")
	errDial      = errors.New("dial")
	errHandshake = errors.New("handshake")
)

// chainName returns the configured chain name, or "" for the default route.
func chainName(c chain.Chainer) string {
	if cn, ok := c.(chainNamer); ok {
		return cn.Name()
	}
	return ""
}

