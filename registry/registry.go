package registry

import (
	"errors"
	"io"
	"sync"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/core/service"
)

var (
	ErrDup = errors.New("registry: duplicate object")
)

var (
	listenerReg  Registry[NewListener]  = new(listenerRegistry)
	handlerReg   Registry[NewHandler]   = new(handlerRegistry)
	dialerReg    Registry[NewDialer]    = new(dialerRegistry)
	connectorReg Registry[NewConnector] = new(connectorRegistry)

	serviceReg   Registry[service.Service]     = new(serviceRegistry)
	chainReg     Registry[chain.Chainer]       = new(chainRegistry)
	hopReg       Registry[chain.Hop]           = new(hopRegistry)
	autherReg    Registry[auth.Authenticator]  = new(autherRegistry)
	admissionReg Registry[admission.Admission] = new(admissionRegistry)
	bypassReg    Registry[bypass.Bypass]       = new(bypassRegistry)
	resolverReg  Registry[resolver.Resolver]   = new(resolverRegistry)
	hostsReg     Registry[hosts.HostMapper]    = new(hostsRegistry)
	recorderReg  Registry[recorder.Recorder]   = new(recorderRegistry)

	trafficLimiterReg Registry[traffic.TrafficLimiter] = new(trafficLimiterRegistry)
	connLimiterReg    Registry[conn.ConnLimiter]       = new(connLimiterRegistry)
	rateLimiterReg    Registry[rate.RateLimiter]       = new(rateLimiterRegistry)
)

type Registry[T any] interface {
	Register(name string, v T) error
	Unregister(name string)
	IsRegistered(name string) bool
	Get(name string) T
	GetAll() map[string]T
}

type registry[T any] struct {
	m sync.Map
}

func (r *registry[T]) Register(name string, v T) error {
	if name == "" {
		return nil
	}
	if _, loaded := r.m.LoadOrStore(name, v); loaded {
		return ErrDup
	}

	return nil
}

func (r *registry[T]) Unregister(name string) {
	if v, ok := r.m.Load(name); ok {
		if closer, ok := v.(io.Closer); ok {
			closer.Close()
		}
		r.m.Delete(name)
	}
}

func (r *registry[T]) IsRegistered(name string) bool {
	_, ok := r.m.Load(name)
	return ok
}

func (r *registry[T]) Get(name string) (t T) {
	if name == "" {
		return
	}
	v, _ := r.m.Load(name)
	t, _ = v.(T)
	return
}

func (r *registry[T]) GetAll() (m map[string]T) {
	m = make(map[string]T)
	r.m.Range(func(key, value any) bool {
		k, _ := key.(string)
		v, _ := value.(T)
		m[k] = v
		return true
	})
	return
}

func ListenerRegistry() Registry[NewListener] {
	return listenerReg
}

func HandlerRegistry() Registry[NewHandler] {
	return handlerReg
}

func DialerRegistry() Registry[NewDialer] {
	return dialerReg
}

func ConnectorRegistry() Registry[NewConnector] {
	return connectorReg
}

func ServiceRegistry() Registry[service.Service] {
	return serviceReg
}

func ChainRegistry() Registry[chain.Chainer] {
	return chainReg
}

func HopRegistry() Registry[chain.Hop] {
	return hopReg
}

func AutherRegistry() Registry[auth.Authenticator] {
	return autherReg
}

func AdmissionRegistry() Registry[admission.Admission] {
	return admissionReg
}

func BypassRegistry() Registry[bypass.Bypass] {
	return bypassReg
}

func ResolverRegistry() Registry[resolver.Resolver] {
	return resolverReg
}

func HostsRegistry() Registry[hosts.HostMapper] {
	return hostsReg
}

func RecorderRegistry() Registry[recorder.Recorder] {
	return recorderReg
}

func TrafficLimiterRegistry() Registry[traffic.TrafficLimiter] {
	return trafficLimiterReg
}

func ConnLimiterRegistry() Registry[conn.ConnLimiter] {
	return connLimiterReg
}

func RateLimiterRegistry() Registry[rate.RateLimiter] {
	return rateLimiterReg
}
