package selector

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/selector"
	xnet "github.com/go-gost/x/internal/net"
)

type parallelStrategy[T any] struct{}

func ParallelStrategy[T any]() selector.Strategy[T] {
	return &parallelStrategy[T]{}
}

func (s *parallelStrategy[T]) Apply(ctx context.Context, vs ...T) (v T) {
	if len(vs) == 0 {
		return
	}
	if len(vs) == 1 {
		return vs[0]
	}

	nodes := make([]*chain.Node, 0, len(vs))
	for _, node := range vs {
		nodes = append(nodes, any(node).(*chain.Node))
	}

	vn := chain.NewNode("parallel", "", chain.TransportNodeOption(&parallelTransporter{nodes: nodes}))
	return any(vn).(T)
}

type parallelConn struct {
	net.Conn
	node *chain.Node
}

type parallelTransporter struct {
	nodes []*chain.Node
}

func (tr *parallelTransporter) Dial(ctx context.Context, addr string) (net.Conn, error) {
	if len(tr.nodes) == 0 {
		return nil, errors.New("no nodes available")
	}

	ctx, cancel := context.WithCancel(ctx)

	type result struct {
		conn net.Conn
		node *chain.Node
		err  error
	}

	resCh := make(chan result, len(tr.nodes))

	var wg sync.WaitGroup
	for _, node := range tr.nodes {
		wg.Add(1)
		go func(n *chain.Node) {
			defer wg.Done()

			raddr, err := xnet.Resolve(ctx, "ip", n.Addr, n.Options().Resolver, n.Options().HostMapper, logger.Default())
			if err != nil {
				resCh <- result{err: err, node: n}
				return
			}

			cc, err := n.Options().Transport.Dial(ctx, raddr)
			resCh <- result{conn: cc, node: n, err: err}
		}(node)
	}

	var best result
	var errs []error

	for i := 0; i < len(tr.nodes); i++ {
		res := <-resCh
		if res.err != nil {
			errs = append(errs, res.err)
			continue
		}

		best = res
		break
	}

	cancel()

	if best.conn == nil {
		go func() {
			wg.Wait()
			close(resCh)
		}()
		return nil, errors.Join(errs...)
	}

	go func() {
		// Drain the rest of the channel to clean up late successful connections
		for i := len(errs) + 1; i < len(tr.nodes); i++ {
			res := <-resCh
			if res.err == nil && res.conn != nil {
				res.conn.Close()
			}
		}
		wg.Wait()
		close(resCh)
	}()

	return &parallelConn{
		Conn: best.conn,
		node: best.node,
	}, nil
}

func (tr *parallelTransporter) Handshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	pc, ok := conn.(*parallelConn)
	if !ok {
		return conn, nil
	}

	cc, err := pc.node.Options().Transport.Handshake(ctx, pc.Conn)
	if err != nil {
		return nil, err
	}
	pc.Conn = cc

	return pc, nil
}

func (tr *parallelTransporter) Connect(ctx context.Context, conn net.Conn, network, address string) (net.Conn, error) {
	pc, ok := conn.(*parallelConn)
	if !ok {
		return nil, errors.New("invalid connection type")
	}

	return pc.node.Options().Transport.Connect(ctx, pc.Conn, network, address)
}

func (tr *parallelTransporter) Bind(ctx context.Context, conn net.Conn, network, address string, opts ...connector.BindOption) (net.Listener, error) {
	pc, ok := conn.(*parallelConn)
	if !ok {
		return nil, errors.New("invalid connection type")
	}

	return pc.node.Options().Transport.Bind(ctx, pc.Conn, network, address, opts...)
}

func (tr *parallelTransporter) Multiplex() bool {
	return false
}

func (tr *parallelTransporter) Options() *chain.TransportOptions {
	return &chain.TransportOptions{}
}

func (tr *parallelTransporter) Copy() chain.Transporter {
	return &parallelTransporter{
		nodes: append([]*chain.Node(nil), tr.nodes...),
	}
}
