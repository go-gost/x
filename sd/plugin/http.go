package sd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/x/internal/plugin"
)

type sdService struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Node    string `json:"node"`
	Network string `json:"network"`
	Address string `json:"address"`
}

type httpGetResponse struct {
	Services []*sdService `json:"services"`
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

func (p *httpPlugin) Register(ctx context.Context, service *sd.Service, opts ...sd.Option) error {
	if p.client == nil || service == nil {
		return nil
	}

	v, err := json.Marshal(sdService{
		ID:      service.ID,
		Name:    service.Name,
		Node:    service.Node,
		Network: service.Network,
		Address: service.Address,
	})
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

func (p *httpPlugin) Deregister(ctx context.Context, service *sd.Service) error {
	if p.client == nil || service == nil {
		return nil
	}

	v, err := json.Marshal(sdService{
		ID:      service.ID,
		Name:    service.Name,
		Node:    service.Node,
		Network: service.Network,
		Address: service.Address,
	})
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

func (p *httpPlugin) Renew(ctx context.Context, service *sd.Service) error {
	if p.client == nil {
		return nil
	}

	v, err := json.Marshal(sdService{
		ID:      service.ID,
		Name:    service.Name,
		Node:    service.Node,
		Network: service.Network,
		Address: service.Address,
	})
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
			ID:      v.ID,
			Name:    v.Name,
			Node:    v.Node,
			Network: v.Network,
			Address: v.Address,
		})
	}
	return
}
