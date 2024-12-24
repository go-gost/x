package recorder

import (
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/plugin/recorder/proto"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.RecorderClient
	log    logger.Logger
}

// NewGRPCPlugin creates a Recorder plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) recorder.Recorder {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":     "recorder",
		"recorder": name,
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
		p.client = proto.NewRecorderClient(conn)
	}
	return p
}

func (p *grpcPlugin) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	if p.client == nil {
		return nil
	}

	var options recorder.RecordOptions
	for _, opt := range opts {
		opt(&options)
	}

	md, _ := json.Marshal(options.Metadata)

	reply, err := p.client.Record(ctx,
		&proto.RecordRequest{
			Data:     b,
			Metadata: md,
		})
	if err != nil {
		p.log.Error(err)
		return err
	}
	if reply == nil || !reply.Ok {
		return errors.New("record failed")
	}
	return nil
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
