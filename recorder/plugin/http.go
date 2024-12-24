package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/x/internal/plugin"
)

type httpPluginRequest struct {
	Data     []byte `json:"data"`
	Metadata []byte `json:"metadata"`
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

// NewHTTPPlugin creates an Recorder plugin based on HTTP.
func NewHTTPPlugin(name string, url string, opts ...plugin.Option) recorder.Recorder {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	return &httpPlugin{
		url:    url,
		client: plugin.NewHTTPClient(&options),
		header: options.Header,
		log: logger.Default().WithFields(map[string]any{
			"kind":     "recorder",
			"recorder": name,
		}),
	}
}

func (p *httpPlugin) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	if len(b) == 0 || p.client == nil {
		return nil
	}

	var options recorder.RecordOptions
	for _, opt := range opts {
		opt(&options)
	}

	md, _ := json.Marshal(options.Metadata)

	rb := httpPluginRequest{
		Data:     b,
		Metadata: md,
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
		return errors.New(resp.Status)
	}

	res := httpPluginResponse{}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return err
	}

	if !res.OK {
		return errors.New("record failed")
	}
	return nil
}
