package admission

import (
	"context"
	"io"

	admission_pkg "github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/admission/proto"
	"google.golang.org/grpc"
)

type grpcPluginAdmission struct {
	conn   grpc.ClientConnInterface
	client proto.AdmissionClient
	log    logger.Logger
}

// NewGRPCPluginAdmission creates an Admission plugin based on gRPC.
func NewGRPCPluginAdmission(name string, conn grpc.ClientConnInterface) admission_pkg.Admission {
	p := &grpcPluginAdmission{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":      "admission",
			"admission": name,
		}),
	}
	if conn != nil {
		p.client = proto.NewAdmissionClient(conn)
	}
	return p
}

func (p *grpcPluginAdmission) Admit(ctx context.Context, addr string) bool {
	if p.client == nil {
		return false
	}

	r, err := p.client.Admit(ctx,
		&proto.AdmissionRequest{
			Addr: addr,
		})
	if err != nil {
		p.log.Error(err)
		return false
	}
	return r.Ok
}

func (p *grpcPluginAdmission) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
