package recorder

import (
	"context"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/plugin/recorder/proto"
	"google.golang.org/grpc"
)

type grpcPluginRecorder struct {
	conn   grpc.ClientConnInterface
	client proto.RecorderClient
	log    logger.Logger
}

// NewGRPCPluginRecorder creates a plugin recorder.
func NewGRPCPluginRecorder(name string, conn grpc.ClientConnInterface) recorder.Recorder {
	p := &grpcPluginRecorder{
		conn: conn,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "recorder",
			"recorder": name,
		}),
	}
	if conn != nil {
		p.client = proto.NewRecorderClient(conn)
	}
	return p
}

func (p *grpcPluginRecorder) Record(ctx context.Context, b []byte) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Record(context.Background(),
		&proto.RecordRequest{
			Data: b,
		})
	if err != nil {
		p.log.Error(err)
		return err
	}
	return nil
}

func (p *grpcPluginRecorder) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
