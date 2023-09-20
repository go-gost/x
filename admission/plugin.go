package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/admission/proto"
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginAdmission struct {
	conn   grpc.ClientConnInterface
	client proto.AdmissionClient
	log    logger.Logger
}

// NewGRPCPluginAdmission creates an Admission plugin based on gRPC.
func NewGRPCPluginAdmission(name string, addr string, opts ...plugin.Option) admission.Admission {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":      "admission",
		"admission": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPluginAdmission{
		conn: conn,
		log:  log,
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

type httpAdmissionRequest struct {
	Addr string `json:"addr"`
}

type httpAdmissionResponse struct {
	OK bool `json:"ok"`
}

type httpPluginAdmission struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginAdmission creates an Admission plugin based on HTTP.
func NewHTTPPluginAdmission(name string, url string, opts ...plugin.Option) admission.Admission {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginAdmission{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":      "admission",
			"admission": name,
		}),
	}
}

func (p *httpPluginAdmission) Admit(ctx context.Context, addr string) (ok bool) {
	if p.client == nil {
		return
	}

	rb := httpAdmissionRequest{
		Addr: addr,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return
	}

	req, err := http.NewRequest(http.MethodPost, p.url, bytes.NewReader(v))
	if err != nil {
		return
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	res := httpAdmissionResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	return res.OK
}
