package proto

import (
	context "context"
	"strings"

	grpc "google.golang.org/grpc"
)

type GostTunelClientX interface {
	TunnelX(ctx context.Context, method string, opts ...grpc.CallOption) (GostTunel_TunnelClient, error)
}
type gostTunelClientX struct {
	cc grpc.ClientConnInterface
}

func NewGostTunelClientX(cc grpc.ClientConnInterface) GostTunelClientX {
	return &gostTunelClientX{
		cc: cc,
	}
}

func (c *gostTunelClientX) TunnelX(ctx context.Context, method string, opts ...grpc.CallOption) (GostTunel_TunnelClient, error) {
	sd := ServerDesc(method)
	method = "/" + sd.ServiceName + "/" + sd.Streams[0].StreamName
	stream, err := c.cc.NewStream(ctx, &sd.Streams[0], method, opts...)
	if err != nil {
		return nil, err
	}
	x := &gostTunelTunnelClient{stream}
	return x, nil
}

func RegisterGostTunelServerX(s grpc.ServiceRegistrar, srv GostTunelServer, method string) {
	sd := ServerDesc(method)
	s.RegisterService(&sd, srv)
}

func ServerDesc(method string) grpc.ServiceDesc {
	serviceName, streamName := parsingMethod(method)

	return grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: GostTunel_ServiceDesc.HandlerType,
		Methods:     GostTunel_ServiceDesc.Methods,
		Streams: []grpc.StreamDesc{
			{
				StreamName:    streamName,
				Handler:       GostTunel_ServiceDesc.Streams[0].Handler,
				ServerStreams: GostTunel_ServiceDesc.Streams[0].ServerStreams,
				ClientStreams: GostTunel_ServiceDesc.Streams[0].ClientStreams,
			},
		},
		Metadata: GostTunel_ServiceDesc.Metadata,
	}

}

func parsingMethod(method string) (string, string) {
	serviceName := GostTunel_ServiceDesc.ServiceName
	streamName := GostTunel_ServiceDesc.Streams[0].StreamName
	v := strings.SplitN(strings.Trim(method, "/"), "/", 2)
	if len(v) == 1 && v[0] != "" {
		serviceName = v[0]
	}
	if len(v) == 2 {
		serviceName = v[0]
		streamName = strings.Replace(v[1], "/", "-", -1)
	}

	return serviceName, streamName
}
