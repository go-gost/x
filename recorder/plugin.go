package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/plugin/recorder/proto"
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginRecorder struct {
	conn   grpc.ClientConnInterface
	client proto.RecorderClient
	log    logger.Logger
}

// NewGRPCPluginRecorder creates a Recorder plugin based on gRPC.
func NewGRPCPluginRecorder(name string, addr string, opts ...plugin.Option) recorder.Recorder {
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

	p := &grpcPluginRecorder{
		conn: conn,
		log:  log,
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

type httpRecorderRequest struct {
	Data []byte `json:"data"`
}

type httpRecorderResponse struct {
	OK bool `json:"ok"`
}

type httpPluginRecorder struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginRecorder creates an Recorder plugin based on HTTP.
func NewHTTPPluginRecorder(name string, url string, opts ...plugin.Option) recorder.Recorder {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginRecorder{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":    "recorder",
			"recorder": name,
		}),
	}
}

func (p *httpPluginRecorder) Record(ctx context.Context, b []byte) error {
	if len(b) == 0 || p.client == nil {
		return nil
	}

	rb := httpRecorderRequest{
		Data: b,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		return err
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s", resp.Status)
	}

	res := httpRecorderResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	if !res.OK {
		return errors.New("record failed")
	}
	return nil
}
