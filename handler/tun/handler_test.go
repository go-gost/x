package tun

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	xlogger "github.com/go-gost/x/logger"
)

// fakeRouter only needs Options: the mode decision reads Options().Chain and
// never dials.
type fakeRouter struct {
	options *chain.RouterOptions
}

func (r *fakeRouter) Options() *chain.RouterOptions { return r.options }

func (r *fakeRouter) Dial(ctx context.Context, network, address string, opts ...chain.DialOption) (net.Conn, error) {
	return nil, errors.New("unexpected dial")
}

func (r *fakeRouter) Bind(ctx context.Context, network, address string, opts ...chain.BindOption) (net.Listener, error) {
	return nil, errors.New("unexpected bind")
}

type fakeChainer struct{}

func (fakeChainer) Route(ctx context.Context, network, address string, opts ...chain.RouteOption) chain.Route {
	return nil
}

type fakeHop struct{ node *chain.Node }

func (h fakeHop) Select(ctx context.Context, opts ...hop.SelectOption) *chain.Node { return h.node }

func newTestHandler(hp hop.Hop, router chain.Router) *tunHandler {
	opts := []handler.Option{handler.LoggerOption(xlogger.Nop())}
	if router != nil {
		opts = append(opts, handler.RouterOption(router))
	}
	h := NewHandler(opts...).(*tunHandler)
	if hp != nil {
		h.Forward(hp)
	}
	return h
}

func TestSelectTarget(t *testing.T) {
	chained := &fakeRouter{options: &chain.RouterOptions{Chain: fakeChainer{}}}
	plain := &fakeRouter{options: &chain.RouterOptions{}}

	tests := []struct {
		name       string
		hop        hop.Hop
		router     chain.Router
		wantClient bool
		wantAddr   string
	}{
		{
			name:       "forwarder node",
			hop:        fakeHop{node: chain.NewNode("n0", "1.2.3.4:8421")},
			router:     chained,
			wantClient: true,
			wantAddr:   "1.2.3.4:8421",
		},
		{
			name:       "forwarder with no node falls back to server",
			hop:        fakeHop{},
			router:     chained,
			wantClient: false,
		},
		{
			name:       "chain without forwarder is client mode with no address",
			router:     chained,
			wantClient: true,
			wantAddr:   "",
		},
		{
			name:       "no forwarder, no chain is server mode",
			router:     plain,
			wantClient: false,
		},
		{
			name:       "nil router is server mode",
			router:     nil,
			wantClient: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newTestHandler(tt.hop, tt.router)
			addr, client := h.selectTarget(context.Background())
			if client != tt.wantClient {
				t.Fatalf("client mode = %v, want %v", client, tt.wantClient)
			}
			if addr != tt.wantAddr {
				t.Fatalf("dial addr = %q, want %q", addr, tt.wantAddr)
			}
		})
	}
}
