package observer

import (
	"context"
	"errors"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/plugin/observer/proto"
	"github.com/go-gost/x/internal/plugin"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/go-gost/x/service"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.ObserverClient
	log    logger.Logger
}

// NewGRPCPlugin creates an Observer plugin based on gRPC.
// On connection error it returns a no-op observer that logs and discards
// events rather than nil, so callers can always call Observe safely.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) observer.Observer {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":     "observer",
		"observer": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
		return &grpcPlugin{log: log} // no-op: client is nil, Observe returns nil
	}

	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewObserverClient(conn)
	}
	return p
}

func (p *grpcPlugin) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	if p.client == nil || len(events) == 0 {
		return nil
	}

	var req proto.ObserveRequest

	for _, event := range events {
		switch event.Type() {
		case observer.EventStatus:
			ev := event.(service.ServiceEvent)
			req.Events = append(req.Events, &proto.Event{
				Kind:    ev.Kind,
				Service: ev.Service,
				Type:    string(event.Type()),
				Status: &proto.ServiceStatus{
					State: string(ev.State),
					Msg:   ev.Msg,
				},
			})
		case observer.EventStats:
			ev := event.(xstats.StatsEvent)
			req.Events = append(req.Events, &proto.Event{
				Kind:    ev.Kind,
				Service: ev.Service,
				Client:  ev.Client,
				Type:    string(event.Type()),
				Stats: &proto.Stats{
					TotalConns:   ev.TotalConns,
					CurrentConns: ev.CurrentConns,
					InputBytes:   ev.InputBytes,
					OutputBytes:  ev.OutputBytes,
					TotalErrs:    ev.TotalErrs,
				},
			})
		default:
			p.log.Warnf("unknown event type: %s", event.Type())
		}
	}
	reply, err := p.client.Observe(ctx, &req)
	if err != nil {
		p.log.Error(err)
		return err
	}
	if reply == nil || !reply.Ok {
		return errors.New("observe failed")
	}
	return nil
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
