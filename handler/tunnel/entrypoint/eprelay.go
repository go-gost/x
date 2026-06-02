package entrypoint

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/relay"
	xnet "github.com/go-gost/x/internal/net"
	xrecorder "github.com/go-gost/x/recorder"
)

// handleConnect (entrypoint relay) processes a relay-protocol connection
// arriving at the entrypoint.
//
// Flow:
//  1. Read relay.Request (extracts src/dst address, tunnelID, network).
//  2. Dialer.Dial() → pool.Get() → GetConn() → mux.OpenStream().
//  3. Write StatusOK response to the public connection.
//  4. Write relay.Response with src/dst address features to the mux stream.
//  5. Pipe(publicConn, muxStream).
//
// Unlike tunnelHandler.handleConnect, this path does not use ingress routing
// or bypass checks — the relay request already contains the tunnel ID.
// Also unlike handleConnect, there is no local-vs-remote framing difference:
// the entrypoint always writes StatusOK + address features regardless of node.
func (ep *Entrypoint) handleConnect(ctx context.Context, conn net.Conn, ro *xrecorder.HandlerRecorderObject, log logger.Logger) (err error) {
	req := relay.Request{}
	if _, err := req.ReadFrom(conn); err != nil {
		return err
	}

	resp := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	var srcAddr, dstAddr string
	network := "tcp"
	var tunnelID relay.TunnelID
	for _, f := range req.Features {
		switch f.Type() {
		case relay.FeatureAddr:
			if feature, _ := f.(*relay.AddrFeature); feature != nil {
				v := net.JoinHostPort(feature.Host, strconv.Itoa(int(feature.Port)))
				if srcAddr != "" {
					dstAddr = v
				} else {
					srcAddr = v
				}
			}
		case relay.FeatureTunnel:
			if feature, _ := f.(*relay.TunnelFeature); feature != nil {
				tunnelID = relay.NewTunnelID(feature.ID[:])
			}
		case relay.FeatureNetwork:
			if feature, _ := f.(*relay.NetworkFeature); feature != nil {
				network = feature.Network.String()
			}
		}
	}

	if tunnelID.IsZero() {
		resp.Status = relay.StatusBadRequest
		resp.WriteTo(conn)
		return errBadTunnelID
	}

	ro.ClientID = tunnelID.String()

	cc, _, cid, err := ep.dialFn(ctx, network, tunnelID.String())
	if err != nil {
		log.Error(err)
		resp.Status = relay.StatusServiceUnavailable
		resp.WriteTo(conn)
		return err
	}
	defer cc.Close()

	log.Debugf("new connection to tunnel: %s, connector: %s", tunnelID, cid)

	if _, err := resp.WriteTo(conn); err != nil {
		log.Error(err)
		return err
	}

	features := relay.Response{
		Version: relay.Version1,
		Status:  relay.StatusOK,
	}

	af := &relay.AddrFeature{}
	af.ParseFrom(srcAddr)
	features.Features = append(features.Features, af) // src address

	af = &relay.AddrFeature{}
	af.ParseFrom(dstAddr)
	features.Features = append(features.Features, af) // dst address

	if _, err := features.WriteTo(cc); err != nil {
		log.Error(err)
		cc.Close()
		return err
	}

	t := time.Now()
	log.Debugf("%s <-> %s", conn.RemoteAddr(), cc.RemoteAddr())
	// xnet.Transport(conn, cc)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(t),
	}).Debugf("%s >-< %s", conn.RemoteAddr(), cc.RemoteAddr())

	return nil
}

// errBadTunnelID is returned when a relay request arrives at the entrypoint
// without a valid tunnel feature (zero tunnel ID).
var errBadTunnelID = fmt.Errorf("invalid tunnel ID")