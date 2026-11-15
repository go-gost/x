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
//	"resolve"   — host resolution for the node failed, no dial was attempted
//	"dial"      — the node's own connector rejected/failed the dial
//	"handshake" — the node's transport handshake failed
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

// resetPath clears any hops and chain name recorded on the attempt. Chain
// dials retry dials on each ECH retry, and each candidate iteration
// re-invokes connect; the record must not show stale attempts.
func resetPath(ctx context.Context, name string) {
	reset := func() {
		if ro := ioctx.RecorderObjectFromContext(ctx); ro != nil {
			ro.Path = nil
			ro.Chain = ""
		}
	}
	reset()
}

// RecordTargetHop appends the final target dial as a new hop element.
func RecordTargetHop(ctx context.Context, addr string, d time.Duration, err error) {
	if ro := ioctx.RecorderObjectFromContext(ctx); ro != nil {
		theNode := xrecorder.PathHop{Hop: len(ro.Path), Chain: "", Node: "", Addr: addr, ConnectMs: hopMs(d)}
		if err != nil {
			theNode.Err = classifyTargetErr(err)
		}
		ro.Path = append(ro.Path, theNode)
	}
}

func classifyTargetErr(err error) string {
	if err == nil {
		return ""
	}
	e := err.Error()
	switch {
	case strContains(e, "handshake") || strContains(e, "certificate"):
		return "handshake"
	case strContains(e, "dial"), strContains(e, "connect"):
		return "dial"
	case strContains(e, "no such host"), strContains(e, "no route to host"), strContains(e, "i/o timeout"):
		return "resolve"
	default:
		return "dial"
	}
}

func strContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
