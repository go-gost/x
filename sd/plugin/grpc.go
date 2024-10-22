package sd

import (
	"context"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/plugin/sd/proto"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.SDClient
	log    logger.Logger
}

// NewGRPCPlugin creates an SD plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) sd.SD {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind": "sd",
		"sd":   name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPlugin{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewSDClient(conn)
	}
	return p
}

func (p *grpcPlugin) Register(ctx context.Context, service *sd.Service, opts ...sd.Option) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Register(ctx,
		&proto.RegisterRequest{
			Service: &proto.Service{
				Id:      service.ID,
				Name:    service.Name,
				Node:    service.Node,
				Network: service.Network,
				Address: service.Address,
			},
		})
	if err != nil {
		p.log.Error(err)
		return err
	}
	return nil
}

func (p *grpcPlugin) Deregister(ctx context.Context, service *sd.Service) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Deregister(ctx, &proto.DeregisterRequest{
		Service: &proto.Service{
			Id:      service.ID,
			Name:    service.Name,
			Node:    service.Node,
			Network: service.Network,
			Address: service.Address,
		},
	})
	return err
}

func (p *grpcPlugin) Renew(ctx context.Context, service *sd.Service) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Renew(ctx, &proto.RenewRequest{
		Service: &proto.Service{
			Id:      service.ID,
			Name:    service.Name,
			Node:    service.Node,
			Network: service.Network,
			Address: service.Address,
		},
	})
	return err
}

func (p *grpcPlugin) Get(ctx context.Context, name string) ([]*sd.Service, error) {
	if p.client == nil {
		return nil, nil
	}

	r, err := p.client.Get(ctx, &proto.GetServiceRequest{
		Name: name,
	})
	if err != nil {
		return nil, err
	}

	var services []*sd.Service
	for _, v := range r.Services {
		if v == nil {
			continue
		}
		services = append(services, &sd.Service{
			ID:      v.Id,
			Name:    v.Name,
			Node:    v.Node,
			Network: v.Network,
			Address: v.Address,
		})
	}
	return services, nil
}

func (p *grpcPlugin) Close() error {
	if p.conn == nil {
		return nil
	}

	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
