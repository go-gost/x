package bypass

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/bypass/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.BypassClient
	log    logger.Logger
}

// NewGRPCPlugin creates a Bypass plugin based on gRPC.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) bypass.Bypass {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":   "bypass",
		"bypass": name,
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
		p.client = proto.NewBypassClient(conn)
	}
	return p
}

func (p *grpcPlugin) Contains(ctx context.Context, addr string) bool {
	if p.client == nil {
		return true
	}

	r, err := p.client.Bypass(ctx,
		&proto.BypassRequest{
			Addr:   addr,
			Client: string(auth_util.IDFromContext(ctx)),
		})
	if err != nil {
		p.log.Error(err)
		return true
	}
	return r.Ok
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpPluginRequest struct {
	Addr   string `json:"addr"`
	Client string `json:"client"`
}

type httpPluginResponse struct {
	OK bool `json:"ok"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Bypass plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) bypass.Bypass {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": name,
		}),
	}
}

func (p *httpPlugin) Contains(ctx context.Context, addr string) (ok bool) {
	if p.client == nil {
		return
	}

	rb := httpPluginRequest{
		Addr:   addr,
		Client: string(auth_util.IDFromContext(ctx)),
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

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	return res.OK
}
