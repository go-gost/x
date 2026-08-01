package forwarder

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	xnet "github.com/go-gost/x/internal/net"
	"github.com/go-gost/x/internal/util/sniffing"
)

// HandleRedis proxies a sniffed Redis connection through a hop-selected node.
// It parses the first RESP message for metadata recording, selects an upstream
// node via resolveRedisNode (which passes ProtoRedis to the hop's protocol
// selector), replays the captured bytes, and pipes traffic bidirectionally.
func (h *Sniffer) HandleRedis(ctx context.Context, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	buf := new(bytes.Buffer)
	if err := sniffing.ParseRedisMetadata(io.TeeReader(conn, buf), ho.recorderObject); err != nil {
		return err
	}

	ro := ho.recorderObject

	node, cc, err := h.dialRedis(ctx, &ho)
	if err != nil {
		return err
	}
	defer cc.Close()
	ho.node = node

	log := ho.log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	log.Debugf("connected to node %s(%s)", node.Name, node.Addr)

	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	return nil
}

// resolveRedisNode selects an upstream node for a Redis connection via hop
// selection with ProtocolSelectOption. Unlike resolveTLSNode, there is no
// host to route by — routing is driven by ProtocolSelectOption(ProtoRedis)
// and ClientIPSelectOption.
func resolveRedisNode(ctx context.Context, ho *HandleOptions) (node *chain.Node, err error) {
	node = &chain.Node{}
	if ho.hop != nil {
		var clientIP net.IP
		if clientAddr, _ := net.ResolveTCPAddr("tcp", ho.recorderObject.ClientAddr); clientAddr != nil {
			clientIP = clientAddr.IP
		}
		node = ho.hop.Select(ctx,
			hop.ClientIPSelectOption(clientIP),
			hop.ProtocolSelectOption(sniffing.ProtoRedis),
		)
	}
	if node == nil {
		return nil, fmt.Errorf("node not available")
	}
	ho.recorderObject.Node = node.Name
	return node, nil
}

// dialRedis selects a node via resolveRedisNode and establishes a TCP
// connection to the node's address.
func (h *Sniffer) dialRedis(ctx context.Context, ho *HandleOptions) (node *chain.Node, cc net.Conn, err error) {
	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}

	if node = ho.node; node != nil {
		cc, err = dial(ctx, "tcp", node.Addr)
		return
	}

	node, err = resolveRedisNode(ctx, ho)
	if err != nil {
		return
	}

	ro := ho.recorderObject
	addr := node.Addr
	network := "tcp"
	if opts := node.Options(); opts != nil {
		switch opts.Network {
		case "unix":
			network = opts.Network
		default:
			if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
				addr += ":6379"
			}
		}
	} else {
		if _, _, splitErr := net.SplitHostPort(addr); splitErr != nil {
			addr += ":6379"
		}
	}
	ro.Host = addr

	ho.log = ho.log.WithFields(map[string]any{
		"node": node.Name,
		"dst":  fmt.Sprintf("%s/%s", addr, network),
	})
	ho.log.Debugf("find node for redis -> %s(%s)", node.Name, addr)

	cc, err = dial(ctx, network, addr)
	if err != nil {
		if marker := node.Marker(); marker != nil {
			marker.Mark()
		}
		ho.log.Warnf("connect to node %s(%s) failed: %v", node.Name, node.Addr, err)
		return
	}

	if marker := node.Marker(); marker != nil {
		marker.Reset()
	}

	cc = tlsWrapConn(cc, node.Options().TLS)
	return
}
