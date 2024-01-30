package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/logger"
	ctxvalue "github.com/go-gost/x/ctx"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Client   string `json:"client"`
}

type httpPluginResponse struct {
	OK bool   `json:"ok"`
	ID string `json:"id"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Authenticator plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) auth.Authenticator {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":   "auther",
			"auther": name,
		}),
	}
}

func (p *httpPlugin) Authenticate(ctx context.Context, user, password string, opts ...auth.Option) (id string, ok bool) {
	if p.client == nil {
		return
	}

	rb := httpPluginRequest{
		Username: user,
		Password: password,
		Client:   string(ctxvalue.ClientAddrFromContext(ctx)),
	}
	v, err := json.Marshal(&rb)
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(v))
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
	return res.ID, res.OK
}
