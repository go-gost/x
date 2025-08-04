package wrapper

import (
	"context"
	"net"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	xctx "github.com/go-gost/x/ctx"
)

type listener struct {
	net.Listener
	admission admission.Admission
	log       logger.Logger
}

func WrapListener(admission admission.Admission, ln net.Listener) net.Listener {
	if admission == nil {
		return ln
	}
	return &listener{
		Listener:  ln,
		admission: admission,
	}
}

func (ln *listener) Accept() (net.Conn, error) {
	for {
		c, err := ln.Listener.Accept()
		if err != nil {
			return nil, err
		}

		ctx := context.Background()
		if cc, ok := c.(xctx.Context); ok {
			if cv := cc.Context(); cv != nil {
				ctx = cv
			}
		}

		clientAddr := c.RemoteAddr()
		if addr := xctx.SrcAddrFromContext(ctx); addr != nil {
			clientAddr = addr
		}

		if ln.admission != nil &&
			!ln.admission.Admit(ctx, clientAddr.String()) {
			c.Close()
			continue
		}
		return c, err
	}
}
