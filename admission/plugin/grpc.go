// Package admission implements gRPC-based admission plugins.
// An admission plugin delegates the admit/deny decision to an external
// service via gRPC. This allows admission logic to be implemented in
// a separate process using any language supported by protobuf.
//
// The gRPC service definition is in plugin/admission/proto.
package admission

import (
	"context"
	"io"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/plugin/admission/proto"
	"github.com/go-gost/x/internal/plugin"
	"google.golang.org/grpc"
)

// grpcPlugin is an admission controller that delegates to an external
// gRPC admission service.
//
// If the gRPC connection cannot be established at construction time,
// the client field remains nil and Admit returns true (fail-open),
// allowing all traffic through rather than blocking everything.
type grpcPlugin struct {
	conn   grpc.ClientConnInterface
	client proto.AdmissionClient
	log    logger.Logger
}

// NewGRPCPlugin creates an admission controller that communicates with
// an external gRPC admission service at the given address.
//
// The name is used only for log identification. The addr should be a
// gRPC target string (e.g. "127.0.0.1:9000"). Additional plugin options
// (TLS, token, retry) can be passed via opts.
//
// If the connection fails, the plugin logs the error and operates in
// fail-open mode: all admission requests return true.
func NewGRPCPlugin(name string, addr string, opts ...plugin.Option) admission.Admission {
	var options plugin.Options
	for _, opt := range opts {
		opt(&options)
	}

	log := logger.Default().WithFields(map[string]any{
		"kind":      "admission",
		"admission": name,
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
		p.client = proto.NewAdmissionClient(conn)
	}
	return p
}

// Admit sends an admission request to the external gRPC service.
// It passes the network, address, and service name from the client
// connection.
//
// If the gRPC client is nil (connection failed at startup), it returns
// true (fail-open). If the RPC returns an error, it logs the error and
// returns false.
func (p *grpcPlugin) Admit(ctx context.Context, network, addr string, opts ...admission.Option) bool {
	if p.client == nil {
		return true
	}

	var options admission.Options
	for _, opt := range opts {
		opt(&options)
	}

	r, err := p.client.Admit(ctx,
		&proto.AdmissionRequest{
			Service: options.Service,
			Network: network,
			Addr:    addr,
		})
	if err != nil {
		p.log.Error(err)
		return false
	}
	return r.Ok
}

// Close closes the underlying gRPC connection if it implements io.Closer.
func (p *grpcPlugin) Close() error {
	if closer, ok := p.conn.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}
