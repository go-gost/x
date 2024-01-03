package observer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/x/internal/plugin"
	"github.com/go-gost/x/service"
	"github.com/go-gost/x/stats"
)

type observeRequest struct {
	Events []event `json:"events"`
}

type event struct {
	Kind    string             `json:"kind"`
	Service string             `json:"service"`
	Client  string             `json:"client,omitempty"`
	Type    observer.EventType `json:"type"`
	Stats   *statsEvent        `json:"stats,omitempty"`
	Status  *statusEvent       `json:"status,omitempty"`
}

type statsEvent struct {
	TotalConns   uint64 `json:"totalConns"`
	CurrentConns uint64 `json:"currentConns"`
	InputBytes   uint64 `json:"inputBytes"`
	OutputBytes  uint64 `json:"outputBytes"`
	TotalErrs    uint64 `json:"totalErrs"`
}

type statusEvent struct {
	State string `json:"state"`
	Msg   string `json:"msg"`
}

type observeResponse struct {
	OK bool `json:"ok"`
}

type httpPlugin struct {
	url    string
	client *http.Client
	header http.Header
	log    logger.Logger
}

// NewHTTPPlugin creates an Observer plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) observer.Observer {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "observer",
			"observer": name,
		}),
	}
}

func (p *httpPlugin) Observe(ctx context.Context, events []observer.Event, opts ...observer.Option) error {
	if p.client == nil || len(events) == 0 {
		return nil
	}

	var r observeRequest

	for _, e := range events {
		switch e.Type() {
		case observer.EventStatus:
			ev := e.(service.ServiceEvent)
			r.Events = append(r.Events, event{
				Kind:    ev.Kind,
				Service: ev.Service,
				Type:    ev.Type(),
				Status: &statusEvent{
					State: string(ev.State),
					Msg:   ev.Msg,
				},
			})
		case observer.EventStats:
			ev := e.(stats.StatsEvent)
			r.Events = append(r.Events, event{
				Kind:    ev.Kind,
				Service: ev.Service,
				Client:  ev.Client,
				Type:    ev.Type(),
				Stats: &statsEvent{
					TotalConns:   ev.TotalConns,
					CurrentConns: ev.CurrentConns,
					InputBytes:   ev.InputBytes,
					OutputBytes:  ev.OutputBytes,
					TotalErrs:    ev.TotalErrs,
				},
			})
		}
	}
	v, err := json.Marshal(r)
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
