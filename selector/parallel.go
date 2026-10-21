package selector

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/connector"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/selector"
	xnet "github.com/go-gost/x/internal/net"
)

// parallelMode determines how the racing subset is picked from the
// candidate pool.
type parallelMode int

const (
	// parallelModeRoundRobin rotates through the pool so that every node
	// takes part in the same number of races.
	parallelModeRoundRobin parallelMode = iota
	// parallelModeRandom samples the pool at random.
	parallelModeRandom
)

type parallelConfig struct {
	maxParallel int
	mode        parallelMode
}

// ParallelOption configures the parallel strategy.
type ParallelOption func(*parallelConfig)

// ParallelLimit sets the maximum number of nodes racing concurrently in a
// single connection attempt. The remaining nodes stay in the candidate pool
// and take part in later races. A value <= 0 means no limit: all nodes race.
func ParallelLimit(n int) ParallelOption {
	return func(c *parallelConfig) {
		c.maxParallel = n
	}
}

// ParallelMode sets how the racing subset is selected from the candidate
// pool. Supported modes are "round" (round-robin, the default) and "random".
// An unrecognized mode falls back to round-robin.
func ParallelMode(mode string) ParallelOption {
	return func(c *parallelConfig) {
		switch strings.ToLower(strings.TrimSpace(mode)) {
		case "random", "rand":
			c.mode = parallelModeRandom
		default:
			c.mode = parallelModeRoundRobin
		}
	}
}

type parallelStrategy[T any] struct {
	cfg     parallelConfig
	counter uint64
	rng     *rand.Rand
	mu      sync.Mutex
}

// ParallelStrategy is a strategy for node selector.
// It dials the selected nodes concurrently and uses the first successful
// connection. Without a limit all nodes take part in every race; with a
// limit only that many nodes are picked from the candidate pool for each
// connection attempt.
func ParallelStrategy[T any](opts ...ParallelOption) selector.Strategy[T] {
	cfg := parallelConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &parallelStrategy[T]{
		cfg: cfg,
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
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
		n, ok := any(node).(*chain.Node)
		if !ok {
			return
		}
		nodes = append(nodes, n)
	}

	nodes = s.selectNodes(nodes)

	vn := chain.NewNode("parallel", "", chain.TransportNodeOption(&parallelTransporter{nodes: nodes}))
	return any(vn).(T)
}

// selectNodes returns the subset of nodes taking part in a single race.
// The pool is returned unchanged when no limit is configured or when the pool
// is not larger than the limit.
func (s *parallelStrategy[T]) selectNodes(nodes []*chain.Node) []*chain.Node {
	limit := s.cfg.maxParallel
	if limit <= 0 || limit >= len(nodes) {
		return nodes
	}

	switch s.cfg.mode {
	case parallelModeRandom:
		return s.selectRandom(nodes, limit)
	default:
		return s.selectRoundRobin(nodes, limit)
	}
}

// selectRoundRobin takes limit consecutive nodes starting at an offset that
// advances by limit on every call. The pool is therefore covered evenly over
// time: with 32 nodes and a limit of 4 the races use the disjoint groups
// 0-3, 4-7, 8-11 and so on.
func (s *parallelStrategy[T]) selectRoundRobin(nodes []*chain.Node, limit int) []*chain.Node {
	n := uint64(len(nodes))
	start := (atomic.AddUint64(&s.counter, 1) - 1) * uint64(limit) % n

	selected := make([]*chain.Node, 0, limit)
	for i := 0; i < limit; i++ {
		selected = append(selected, nodes[(start+uint64(i))%n])
	}
	return selected
}

// selectRandom samples limit distinct nodes uniformly at random.
func (s *parallelStrategy[T]) selectRandom(nodes []*chain.Node, limit int) []*chain.Node {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Partial Fisher-Yates shuffle: only the first limit entries are
	// rearranged, the rest of the pool is left untouched.
	pool := make([]*chain.Node, len(nodes))
	copy(pool, nodes)
	for i := 0; i < limit; i++ {
		j := i + s.rng.Intn(len(pool)-i)
		pool[i], pool[j] = pool[j], pool[i]
	}

	selected := make([]*chain.Node, limit)
	copy(selected, pool[:limit])
	return selected
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

// Copy implements chain.Transporter.Copy.
func (tr *parallelTransporter) Copy() chain.Transporter {
	return &parallelTransporter{
		nodes: append([]*chain.Node(nil), tr.nodes...),
	}
}
