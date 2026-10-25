package chain

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/dialer"
	"github.com/go-gost/core/hosts"
	xlogger "github.com/go-gost/x/logger"
	"github.com/stretchr/testify/require"
)

type routeHostMapper struct {
	m map[string][]net.IP
}

func (h *routeHostMapper) Lookup(ctx context.Context, network, host string, opts ...hosts.Option) ([]net.IP, bool) {
	ips, ok := h.m[host]
	return ips, ok
}

// newFailoverNode builds a single node whose host resolves to two IPs
// (10.0.0.1, 10.0.0.2) and records every dialed address in dialed.
func newFailoverNode(t *testing.T, nodeAddr, host string, shouldFail func(addr string) bool, dialed *[]string, mu *sync.Mutex) (*chain.Node, *chainRoute) {
	t.Helper()
	d := &testDialer{dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
		mu.Lock()
		*dialed = append(*dialed, addr)
		mu.Unlock()
		if shouldFail(addr) {
			return nil, errors.New("dial failed")
		}
		return &testConn{}, nil
	}}
	node := chain.NewNode("n1", nodeAddr,
		chain.TransportNodeOption(NewTransport(d, &plainConnector{})),
		chain.HostMapperNodeOption(&routeHostMapper{m: map[string][]net.IP{
			host: {net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
		}}),
	)
	rt := NewRoute()
	rt.addNode(node)
	return node, rt
}

func containsAddr(dialed []string, addr string) bool {
	for _, v := range dialed {
		if v == addr {
			return true
		}
	}
	return false
}

func TestChainRoute_Connect_FailoverToSecondCandidate(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	_, rt := newFailoverNode(t, "failover-1.test:443", "failover-1.test",
		func(addr string) bool { return addr == "10.0.0.1:443" }, &dialed, &mu)

	// Candidates are shuffled, so keep connecting until the broken one has
	// been tried at least once; every attempt must still succeed.
	for i := 0; i < 50; i++ {
		dialed = nil
		conn, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		require.NotNil(t, conn)
		if containsAddr(dialed, "10.0.0.1:443") {
			require.Equal(t, []string{"10.0.0.1:443", "10.0.0.2:443"}, dialed)
			return
		}
	}
	t.Fatal("failing candidate was never dialed")
}

func TestChainRoute_Connect_SpreadAcrossHealthyCandidates(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	_, rt := newFailoverNode(t, "failover-spread.test:443", "failover-spread.test",
		func(string) bool { return false }, &dialed, &mu)

	first := map[string]int{}
	for i := 0; i < 50; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		require.Len(t, dialed, 1)
		first[dialed[0]]++
	}
	require.Contains(t, first, "10.0.0.1:443")
	require.Contains(t, first, "10.0.0.2:443")
}

func TestChainRoute_Connect_DeprioritizesFailedCandidate(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	_, rt := newFailoverNode(t, "failover-deprio.test:443", "failover-deprio.test",
		func(addr string) bool { return addr == "10.0.0.1:443" }, &dialed, &mu)

	// Warm up until the broken candidate has failed once.
	failed := false
	for i := 0; i < 50 && !failed; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		failed = containsAddr(dialed, "10.0.0.1:443")
	}
	require.True(t, failed, "broken candidate was never dialed")

	// Once marked, the healthy candidate must always be tried first.
	for i := 0; i < 20; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		require.Equal(t, "10.0.0.2:443", dialed[0])
	}
}

func TestChainRoute_Connect_AllCandidatesFail(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	node, rt := newFailoverNode(t, "failover-allfail.test:443", "failover-allfail.test",
		func(string) bool { return true }, &dialed, &mu)

	conn, err := rt.connect(context.Background(), xlogger.Nop())
	require.Error(t, err)
	require.Nil(t, conn)
	require.Len(t, dialed, 2)
	require.EqualValues(t, 1, node.Marker().Count())
}

func TestOrderCandidates_ExpiresAfterTTL(t *testing.T) {
	oldNow, oldTTL := timeNow, addrFailTTL
	t.Cleanup(func() { timeNow, addrFailTTL = oldNow, oldTTL })

	failedAt := time.Now()
	timeNow = func() time.Time { return failedAt }
	addrFailTTL = 30 * time.Second

	nodeAddr := "failover-ttl.test:443"
	markAddrFailed(nodeAddr, "10.0.0.1:443")
	require.Equal(t, "10.0.0.2:443", orderCandidates(nodeAddr, []string{"10.0.0.1:443", "10.0.0.2:443"})[0])

	timeNow = func() time.Time { return failedAt.Add(31 * time.Second) }
	require.Len(t, orderCandidates(nodeAddr, []string{"10.0.0.1:443", "10.0.0.2:443"}), 2)
	_, ok := failedAddrs.Load(addrKey(nodeAddr, "10.0.0.1:443"))
	require.False(t, ok, "expired failure record must be dropped")
}

func TestMarkAddrOK_ClearsFailure(t *testing.T) {
	nodeAddr := "failover-ok.test:443"
	markAddrFailed(nodeAddr, "10.0.0.1:443")
	markAddrOK(nodeAddr, "10.0.0.1:443")
	_, ok := failedAddrs.Load(addrKey(nodeAddr, "10.0.0.1:443"))
	require.False(t, ok)
}

func TestChainRoute_Connect_HandshakeFailureDeprioritizes(t *testing.T) {
	var mu sync.Mutex
	var dialed []string
	var lastDialed string
	d := &testDialer{dialFn: func(ctx context.Context, addr string, opts ...dialer.DialOption) (net.Conn, error) {
		mu.Lock()
		dialed = append(dialed, addr)
		lastDialed = addr
		mu.Unlock()
		return &testConn{}, nil
	}}
	c := &testConnector{handshakeFn: func(ctx context.Context, conn net.Conn) (net.Conn, error) {
		if lastDialed == "10.0.0.1:443" {
			return nil, errors.New("handshake failed")
		}
		return conn, nil
	}}
	node := chain.NewNode("n1", "failover-hs.test:443",
		chain.TransportNodeOption(NewTransport(d, c)),
		chain.HostMapperNodeOption(&routeHostMapper{m: map[string][]net.IP{
			"failover-hs.test": {net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
		}}),
	)
	rt := NewRoute()
	rt.addNode(node)

	failed := false
	for i := 0; i < 50 && !failed; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		failed = containsAddr(dialed, "10.0.0.1:443")
	}
	require.True(t, failed, "handshake-failing candidate was never tried")

	for i := 0; i < 20; i++ {
		dialed = nil
		_, err := rt.connect(context.Background(), xlogger.Nop())
		require.NoError(t, err)
		require.Equal(t, "10.0.0.2:443", dialed[0])
	}
}
