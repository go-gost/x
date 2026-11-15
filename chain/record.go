package chain

import (
	"context"
	"errors"
	"time"

	"github.com/go-gost/core/chain"
	ioctx "github.com/go-gost/x/internal/ctx"
	xrecorder "github.com/go-gost/x/recorder"
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


// recordChainName writes the chain name into the recorder object carried in
// ctx (if any). It is called once per route, on every dial — “record” means
// "attach to the in-flight record".
func recordChainName(ctx context.Context, name string) {
	if ro := ioctx.RecorderObjectFromContext(ctx); ro != nil && ro.Chain == "" {
		ro.Chain = name
	}
}

// recordPath appends one structured hop onto the recorder carried in ctx (if
// any). It is zero-allocation for the common no-recorder case.
func recordPath(ctx context.Context, hop xrecorder.PathHop) {
	if ro := ioctx.RecorderObjectFromContext(ctx); ro != nil {
		ro.Path = append(ro.Path, hop)
	}
}

// hopMs casts a duration to milliseconds, clamped to at least 1 for metrics.
func hopMs(d time.Duration) uint64 {
	ms := uint64(d.Milliseconds())
	if ms == 0 {
		return 1
	}
	return ms
}
