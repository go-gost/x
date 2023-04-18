package admission

import (
	"context"

	admission_pkg "github.com/go-gost/core/admission"
	"github.com/go-gost/plugin/admission/proto"
	xlogger "github.com/go-gost/x/logger"
)

type pluginAdmission struct {
	client  proto.AdmissionClient
	options options
}

// NewPluginAdmission creates a plugin admission.
func NewPluginAdmission(opts ...Option) admission_pkg.Admission {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	if options.logger == nil {
		options.logger = xlogger.Nop()
	}

	p := &pluginAdmission{
		options: options,
	}
	if options.client != nil {
		p.client = proto.NewAdmissionClient(options.client)
	}
	return p
}

func (p *pluginAdmission) Admit(ctx context.Context, addr string) bool {
	if p.client == nil {
		return false
	}

	r, err := p.client.Admit(ctx,
		&proto.AdmissionRequest{
			Addr: addr,
		})
	if err != nil {
		p.options.logger.Error(err)
		return false
	}
	return r.Ok
}

func (p *pluginAdmission) Close() error {
	if p.options.client != nil {
		return p.options.client.Close()
	}
	return nil
}
