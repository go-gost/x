package v5

import (
	"context"
	"errors"
	"net"

	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/gosocks5"
	xctx "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/util/socks"
)

// handleResolve handles a Tor SOCKS5 RESOLVE command (0xF0).
// It resolves a hostname to an IP address via the upstream Tor SOCKS5 proxy.
func (h *socks5Handler) handleResolve(ctx context.Context, conn net.Conn, address string, log logger.Logger) error {
	if !h.md.enableTor {
		return h.rejectCmd(conn, log)
	}

	ctx = xctx.ContextWithSocks5Cmd(ctx, socks.CmdResolve)
	return h.doResolve(ctx, conn, address, log)
}

// handleResolvePTR handles a Tor SOCKS5 RESOLVE_PTR command (0xF1).
// It performs a reverse DNS lookup (IP to hostname) via the upstream Tor SOCKS5 proxy.
func (h *socks5Handler) handleResolvePTR(ctx context.Context, conn net.Conn, address string, log logger.Logger) error {
	if !h.md.enableTor {
		return h.rejectCmd(conn, log)
	}

	ctx = xctx.ContextWithSocks5Cmd(ctx, socks.CmdResolvePTR)
	return h.doResolve(ctx, conn, address, log)
}

// rejectCmd writes a CmdUnsupported reply and returns ErrUnknownCmd.
func (h *socks5Handler) rejectCmd(conn net.Conn, log logger.Logger) error {
	log.Error(ErrUnknownCmd)
	resp := gosocks5.NewReply(gosocks5.CmdUnsupported, nil)
	log.Trace(resp)
	resp.Write(conn)
	return ErrUnknownCmd
}

func (h *socks5Handler) doResolve(ctx context.Context, conn net.Conn, address string, log logger.Logger) error {
	cc, err := h.options.Router.Dial(ctx, "tcp", address)
	if err != nil {
		log.Error(err)
		writeSocksReply(conn, gosocks5.Failure, nil)
		return err
	}
	defer cc.Close()

	// Extract resolved address from the chain connection's metadata.
	var resolvedAddr *gosocks5.Addr
	if mdConn, ok := cc.(md.Metadatable); ok {
		if v := mdConn.Metadata().Get("resolvedAddr"); v != nil {
			resolvedAddr, _ = v.(*gosocks5.Addr)
		}
	}

	if resolvedAddr == nil {
		err = errors.New("socks5: no resolved address in reply")
		log.Error(err)
		writeSocksReply(conn, gosocks5.Failure, nil)
		return err
	}

	log.Debugf("resolved %s -> %s", address, resolvedAddr)
	resp := gosocks5.NewReply(gosocks5.Succeeded, resolvedAddr)
	log.Trace(resp)
	resp.Write(conn)
	return nil
}

func writeSocksReply(conn net.Conn, rep uint8, addr *gosocks5.Addr) error {
	resp := gosocks5.NewReply(rep, addr)
	return resp.Write(conn)
}
