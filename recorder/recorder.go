package recorder

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-gost/core/recorder"
	xctx "github.com/go-gost/x/ctx"
)

// MetadataRecorder wraps a Recorder and automatically appends metadata
// to every Record call.
type MetadataRecorder struct {
	recorder.Recorder
	Metadata any
}

func (r *MetadataRecorder) Record(ctx context.Context, b []byte, opts ...recorder.RecordOption) error {
	if r.Recorder == nil {
		return nil
	}
	if r.Metadata == nil {
		return r.Recorder.Record(ctx, b, opts...)
	}
	return r.Recorder.Record(ctx, b, append(opts, recorder.MetadataRecordOption(r.Metadata))...)
}

const (
	RecorderServiceHandler       = "recorder.service.handler"
	RecorderServiceHandlerSerial = "recorder.service.handler.serial"
	RecorderServiceHandlerTunnel = "recorder.service.handler.tunnel"
)

// HTTPRequestRecorderObject holds the recorded data of an HTTP request.
type HTTPRequestRecorderObject struct {
	ContentLength int64       `json:"contentLength"`
	Header        http.Header `json:"header"`
	Body          []byte      `json:"body"`
}

// HTTPResponseRecorderObject holds the recorded data of an HTTP response.
type HTTPResponseRecorderObject struct {
	ContentLength int64       `json:"contentLength"`
	Header        http.Header `json:"header"`
	Body          []byte      `json:"body"`
}

// HTTPRecorderObject holds the recorded HTTP request and response data
// for a single HTTP transaction.
type HTTPRecorderObject struct {
	Host       string                     `json:"host"`
	Method     string                     `json:"method"`
	Proto      string                     `json:"proto"`
	Scheme     string                     `json:"scheme"`
	URI        string                     `json:"uri"`
	StatusCode int                        `json:"statusCode"`
	Request    HTTPRequestRecorderObject  `json:"request"`
	Response   HTTPResponseRecorderObject `json:"response"`

	// The Original* fields below hold the pre-rewrite values captured by the
	// forwarder HTTP path (x/internal/util/forwarder) when a node configures
	// HTTP rewrites. They are empty/nil on non-forwarder paths or when no
	// rewrite applies, so consumers must not rely on their presence.

	// OriginalHost is the Host value before node HTTP rewrites were applied.
	OriginalHost string `json:"originalHost,omitempty"`
	// OriginalURI is the request URI before node URL/header rewrites were applied.
	OriginalURI string `json:"originalUri,omitempty"`
	// OriginalRequest holds the request header/body before node HTTP rewrites
	// were applied. Nil when no request-side rewrite is configured.
	OriginalRequest *HTTPRequestRecorderObject `json:"originalRequest,omitempty"`
	// OriginalResponse holds the response header/body before node HTTP rewrites
	// were applied. Nil when no response-side rewrite is configured. For a 101
	// Switching Protocols response, only headers are captured (there is no body).
	OriginalResponse *HTTPResponseRecorderObject `json:"originalResponse,omitempty"`
}

// WebsocketRecorderObject holds the recorded data of a WebSocket frame.
type WebsocketRecorderObject struct {
	From    string `json:"from"`
	Fin     bool   `json:"fin"`
	Rsv1    bool   `json:"rsv1"`
	Rsv2    bool   `json:"rsv2"`
	Rsv3    bool   `json:"rsv3"`
	OpCode  int    `json:"opcode"`
	Masked  bool   `json:"masked"`
	MaskKey uint32 `json:"maskKey"`
	Length  int64  `json:"length"`
	Payload []byte `json:"payload"`
}

// TLSRecorderObject holds the recorded data of a TLS handshake.
type TLSRecorderObject struct {
	ServerName        string `json:"serverName"`
	CipherSuite       string `json:"cipherSuite"`
	CompressionMethod uint8  `json:"compressionMethod"`
	Proto             string `json:"proto"`
	Version           string `json:"version"`
	ClientHello       string `json:"clientHello"`
	ServerHello       string `json:"serverHello"`
}

// DNSRecorderObject holds the recorded data of a DNS query and response.
type DNSRecorderObject struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Class    string `json:"class"`
	Type     string `json:"type"`
	Question string `json:"question"`
	Answer   string `json:"answer"`
	Cached   bool   `json:"cached"`
}

// HandlerRecorderObject bundles traffic metadata recorded at the handler
// level — addresses, protocols, transferred bytes, and optional sub-records
// for HTTP, WebSocket, TLS, and DNS traffic.
type HandlerRecorderObject struct {
	Node        string                   `json:"node,omitempty"`
	Service     string                   `json:"service"`
	Labels      map[string]string        `json:"labels,omitempty"`
	Network     string                   `json:"network"`
	RemoteAddr  string                   `json:"remote"`
	LocalAddr   string                   `json:"local"`
	ClientAddr  string                   `json:"client"`
	SrcAddr     string                   `json:"src"`
	DstAddr     string                   `json:"dst"`
	Host        string                   `json:"host"`
	Proto       string                   `json:"proto,omitempty"`
	ClientIP    string                   `json:"clientIP"`
	ClientID    string                   `json:"clientID,omitempty"`
	HTTP        *HTTPRecorderObject      `json:"http,omitempty"`
	Websocket   *WebsocketRecorderObject `json:"websocket,omitempty"`
	TLS         *TLSRecorderObject       `json:"tls,omitempty"`
	DNS         *DNSRecorderObject       `json:"dns,omitempty"`
	Route       string                   `json:"route,omitempty"`
	InputBytes  uint64                   `json:"inputBytes"`
	OutputBytes uint64                   `json:"outputBytes"`
	Redirect    string                   `json:"redirect,omitempty"`
	Err         string                   `json:"err,omitempty"`
	SID         string                   `json:"sid"`
	Duration    time.Duration            `json:"duration"`
	Time        time.Time                `json:"time"`
}

// Record serializes the HandlerRecorderObject as JSON and writes it to r.
// It returns nil if p or r is nil or if p.Time is the zero value.
func (p *HandlerRecorderObject) Record(ctx context.Context, r recorder.Recorder) error {
	if p == nil || r == nil || p.Time.IsZero() {
		return nil
	}

	if p.Labels == nil {
		p.Labels = xctx.LabelsFromContext(ctx)
	}

	data, err := json.Marshal(p)
	if err != nil {
		return err
	}

	return r.Record(ctx, data)
}
