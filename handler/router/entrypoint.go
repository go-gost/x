package router

import (
	"bytes"

	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
)

// handleEntrypoint runs the UDP entrypoint read loop.
//
// The entrypoint is the UDP socket that receives packets from peer
// nodes in the mesh. When this node doesn't have a direct connector
// for a destination, handlePacket forwards the IP packet via
// epConn.WriteTo() to another node's entrypoint. This function is
// the receiving side of that exchange.
//
// # Packet format
//
// Each UDP datagram contains a relay request header followed by the
// raw IP packet:
//
//	┌──────────────────┬─────────────────┐
//	│ Relay Request    │ Raw IP Packet   │
//	│ (TunnelFeature + │                 │
//	│  AddrFeature)    │                 │
//	└──────────────────┴─────────────────┘
//
// The relay request carries the tunnel ID (so we know which router)
// and the gateway address (so we know which connector).
//
// # Forwarding
//
// When a packet arrives, the function:
//  1. Reads the datagram from epConn.
//  2. Parses the relay request prefix to extract the tunnel ID and gateway.
//  3. Looks up the connector in the pool.
//  4. Writes ONLY the raw IP packet (after the relay header) to the
//     connector's writer — the relay header consumed by req.ReadFrom
//     is stripped.
//
// # Error handling
//
// Non-CmdAssociate requests and parse errors are silently skipped
// (the iteration continues). A read error from the underlying socket
// terminates the loop — this typically means the socket was closed.
func (h *routerHandler) handleEntrypoint(log logger.Logger) error {
	buf := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(buf)

	for {
		err := func() error {
			n, addr, err := h.epConn.ReadFrom(buf)
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

			// nn is the number of bytes consumed by the relay header.
			// buf[nn:] is the raw IP packet payload.
			if c := h.pool.Get(routerID, gateway); c != nil {
				if w := c.Writer(); w != nil {
					if _, werr := w.Write(buf[nn:n]); werr != nil {
						log.Error(werr)
					}
				}
			}

			return nil
		}()

		if err != nil {
			return err
		}
	}
}
