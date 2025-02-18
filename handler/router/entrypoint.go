package router

import (
	"bytes"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
)

func (h *routerHandler) handleEntrypoint(log logger.Logger) error {
	var buf [MaxMessageSize]byte

	for {
		err := func() error {
			n, addr, err := h.epConn.ReadFrom(buf[:])
			if err != nil {
				return err
			}

			req := relay.Request{}
			nn, err := req.ReadFrom(bytes.NewReader(buf[:n]))
			if err != nil {
				return nil
			}
			if req.Cmd != relay.CmdAssociate {
				return nil
			}

			var routerID relay.TunnelID
			var gateway string

			for _, f := range req.Features {
				switch f.Type() {
				case relay.FeatureTunnel:
					if feature, _ := f.(*relay.TunnelFeature); feature != nil {
						routerID = feature.ID
					}
				case relay.FeatureAddr:
					if feature, _ := f.(*relay.AddrFeature); feature != nil {
						gateway = feature.Host
					}
				}
			}

			log.Tracef("redirect from %s to %s@%s", addr, gateway, routerID)

			if c := h.pool.Get(routerID, gateway); c != nil {
				if w := c.Writer(); w != nil {
					w.Write(buf[nn:])
				}
			}

			return nil
		}()

		if err != nil {
			return err
		}
	}
}
