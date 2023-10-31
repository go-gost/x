package ingress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

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

func (p *grpcPlugin) Register(ctx context.Context, name string, network, address string, opts ...sd.Option) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Register(ctx,
		&proto.RegisterRequest{
			Name:    name,
			Network: network,
			Address: address,
		})
	if err != nil {
		p.log.Error(err)
		return err
	}
	return nil
}

func (p *grpcPlugin) Deregister(ctx context.Context, name string) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Deregister(ctx, &proto.DeregisterRequest{
		Name: name,
	})
	return err
}

func (p *grpcPlugin) Renew(ctx context.Context, name string) error {
	if p.client == nil {
		return nil
	}

	_, err := p.client.Renew(ctx, &proto.RenewRequest{
		Name: name,
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
			Node:    v.Node,
			Name:    v.Name,
			Network: v.Network,
			Address: v.Address,
		})
	}
	return services, nil
}

func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

type httpRegisterRequest struct {
	Name    string `json:"name"`
	Network string `json:"network"`
	Address string `json:"address"`
}

type httpRegisterResponse struct {
	Ok bool `json:"ok"`
}

type httpDeregisterRequest struct {
	Name string `json:"name"`
}

type httpDeregisterResponse struct {
	Ok bool `json:"ok"`
}

type httpRenewRequest struct {
	Name string `json:"name"`
}

type httpRenewResponse struct {
	Ok bool `json:"ok"`
}

type httpGetRequest struct {
	Name string `json:"name"`
}

type sdService struct {
	Node    string `json:"node"`
	Name    string `json:"name"`
	Network string `json:"network"`
	Address string `json:"address"`
}

type httpGetResponse struct {
	Services []*sdService
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an SD plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) sd.SD {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind": "sd",
			"sd":   name,
		}),
	}
}

func (p *httpPlugin) Register(ctx context.Context, name string, network, address string, opts ...sd.Option) error {
	if p.client == nil {
		return nil
	}

	rb := httpRegisterRequest{
		Name:    name,
		Network: network,
		Address: address,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
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
		return fmt.Errorf(resp.Status)
	}

	return nil
}

func (p *httpPlugin) Deregister(ctx context.Context, name string) error {
	if p.client == nil {
		return nil
	}

	rb := httpDeregisterRequest{
		Name: name,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, p.url, bytes.NewReader(v))
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
		return fmt.Errorf(resp.Status)
	}

	return nil
}

func (p *httpPlugin) Renew(ctx context.Context, name string) error {
	if p.client == nil {
		return nil
	}

	rb := httpRenewRequest{
		Name: name,
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, p.url, bytes.NewReader(v))
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
		return fmt.Errorf(resp.Status)
	}

	return nil
}

func (p *httpPlugin) Get(ctx context.Context, name string) (services []*sd.Service, err error) {
	if p.client == nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return
	}

	if p.header != nil {
		req.Header = p.header.Clone()
	}
	req.Header.Set("Content-Type", "application/json")

	q := req.URL.Query()
	q.Set("name", name)
	req.URL.RawQuery = q.Encode()

	resp, err := p.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(resp.Status)
	}

	res := &httpGetResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	for _, v := range res.Services {
		if v == nil {
			continue
		}
		services = append(services, &sd.Service{
			Node:    v.Node,
			Name:    v.Name,
			Network: v.Network,
			Address: v.Address,
		})
	}
	return
}
