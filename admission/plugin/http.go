package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/plugin"
)

// httpPluginRequest is the JSON payload sent to the HTTP admission service.
type httpPluginRequest struct {
	Service string `json:"service"`
	Network string `json:"network"`
	Addr    string `json:"addr"`
}

// httpPluginResponse is the JSON response expected from the HTTP
// admission service. OK indicates whether the address is admitted.
type httpPluginResponse struct {
	OK bool `json:"ok"`
}

// httpPlugin is an admission controller that delegates to an external
// HTTP admission service via JSON POST requests.
//
// The HTTP client is created via plugin.NewHTTPClient, which configures
// timeouts, TLS, and token-based authentication from plugin options.
type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an admission controller that communicates with
// an external HTTP admission service at the given URL.
//
// The name is used only for log identification. On each Admit call,
// a JSON-encoded httpPluginRequest is POSTed to the URL. A 200 response
// with {"ok": true} admits the address; any other response denies it.
//
// If the HTTP client is nil, all admission requests return false.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) admission.Admission {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":      "admission",
			"admission": name,
		}),
	}
}

// Admit sends a JSON POST request to the configured HTTP endpoint.
// The request includes the service name, network, and client address.
//
// The address is admitted only if ALL of the following are true:
//   - The HTTP client is non-nil
//   - The request is successfully sent
//   - The response has status 200 OK
//   - The response body decodes as JSON with "ok": true
//
// Any error, non-200 status, or decode failure results in denial.
func (p *httpPlugin) Admit(ctx context.Context, network, addr string, opts ...admission.Option) (ok bool) {
	if p.client == nil {
		return
	}

	var options admission.Options
	for _, opt := range opts {
		opt(&options)
	}

	rb := httpPluginRequest{
		Service: options.Service,
		Network: network,
		Addr:    addr,
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
	return res.OK
}

// Close closes idle connections in the HTTP client's connection pool.
// It does not shut down the client itself.
func (p *httpPlugin) Close() error {
	if p.client != nil {
		if tr := plugin.HTTPClientTransport(p.client); tr != nil {
			tr.CloseIdleConnections()
		}
	}
	return nil
}
