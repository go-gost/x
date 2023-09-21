package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/auth/proto"
	auth_util "github.com/go-gost/x/internal/util/auth"
	"github.com/go-gost/x/internal/util/plugin"
	"google.golang.org/grpc"
)

type grpcPluginAuthenticator struct {
	conn   grpc.ClientConnInterface
	client proto.AuthenticatorClient
	log    logger.Logger
}

// NewGRPCPluginAuthenticator creates an Authenticator plugin based on gRPC.
func NewGRPCPluginAuthenticator(name string, addr string, opts ...plugin.Option) auth.Authenticator {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":   "auther",
		"auther": name,
	})
	conn, err := plugin.NewGRPCConn(addr, &options)
	if err != nil {
		log.Error(err)
	}

	p := &grpcPluginAuthenticator{
		conn: conn,
		log:  log,
	}

	if conn != nil {
		p.client = proto.NewAuthenticatorClient(conn)
	}
	return p
}

// Authenticate checks the validity of the provided user-password pair.
func (p *grpcPluginAuthenticator) Authenticate(ctx context.Context, user, password string) (string, bool) {
	if p.client == nil {
		return "", false
	}

	r, err := p.client.Authenticate(ctx,
		&proto.AuthenticateRequest{
			Username: user,
			Password: password,
			Client:   string(auth_util.ClientAddrFromContext(ctx)),
		})
	if err != nil {
		p.log.Error(err)
		return "", false
	}
	return r.Id, r.Ok
}

func (p *grpcPluginAuthenticator) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpAutherRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Client   string `json:"client"`
}

type httpAutherResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

type httpPluginAuther struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPluginAuthenticator creates an Authenticator plugin based on HTTP.
func NewHTTPPluginAuthenticator(name string, url string, opts ...plugin.Option) auth.Authenticator {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPluginAuther{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "auther",
			"auther": name,
		}),
	}
}

func (p *httpPluginAuther) Authenticate(ctx context.Context, user, password string) (id string, ok bool) {
	if p.client == nil {
		return
	}

	rb := httpAutherRequest{
		Username: user,
		Password: password,
		Client:   string(auth_util.ClientAddrFromContext(ctx)),
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

	res := httpAutherResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return
	}
	return res.ID, res.OK
}
