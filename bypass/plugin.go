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
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginBypass struct {
	conn   grpc.ClientConnInterface
	client proto.BypassClient
	log    logger.Logger
}

// NewGRPCPluginBypass creates a Bypass plugin based on gRPC.
func NewGRPCPluginBypass(name string, addr string, opts ...plugin.Option) bypass.Bypass {
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

	p := &grpcPluginBypass{
		conn: conn,
		log:  log,
	}
	if conn != nil {
		p.client = proto.NewBypassClient(conn)
	}
	return p
}

func (p *grpcPluginBypass) Contains(ctx context.Context, addr string) bool {
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

func (p *grpcPluginBypass) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpBypassRequest struct {
	Addr   string `json:"addr"`
	Client string `json:"client"`
}

type httpBypassResponse struct {
	OK bool `json:"ok"`
}

type httpPluginBypass struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginBypass creates an Bypass plugin based on HTTP.
func NewHTTPPluginBypass(name string, url string, opts ...plugin.Option) bypass.Bypass {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginBypass{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "bypass",
			"bypass": name,
		}),
	}
}

func (p *httpPluginBypass) Contains(ctx context.Context, addr string) (ok bool) {
	if p.client == nil {
		return
	}

	rb := httpBypassRequest{
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

	res := httpBypassResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	return res.OK
}
