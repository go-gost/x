package registry

import (
	"errors"
	"io"
	"sync"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/auth"
	"github.com/go-gost/core/bypass"
	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/ingress"
	"github.com/go-gost/core/limiter/conn"
	"github.com/go-gost/core/limiter/rate"
	"github.com/go-gost/core/limiter/traffic"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/recorder"
	reg "github.com/go-gost/core/registry"
	"github.com/go-gost/core/resolver"
	"github.com/go-gost/core/router"
	"github.com/go-gost/core/rewriter"
	"github.com/go-gost/core/sd"
	"github.com/go-gost/core/service"
	"github.com/go-gost/x/limiter/quota"
)

var (
	// ErrDup is returned by Register when a value is already registered
	// under the given name.
	ErrDup = errors.New("registry: duplicate object")
)

var (
	listenerReg  reg.Registry[NewListener]         = new(listenerRegistry)
	handlerReg   reg.Registry[NewHandler]          = new(handlerRegistry)
	dialerReg    reg.Registry[NewDialer]           = new(dialerRegistry)
	connectorReg reg.Registry[NewConnector]        = new(connectorRegistry)
	serviceReg   reg.Registry[service.Service]     = new(serviceRegistry)
	chainReg     reg.Registry[chain.Chainer]       = new(chainRegistry)
	hopReg       reg.Registry[hop.Hop]             = new(hopRegistry)
	autherReg    reg.Registry[auth.Authenticator]  = new(autherRegistry)
	admissionReg reg.Registry[admission.Admission] = new(admissionRegistry)
	bypassReg    reg.Registry[bypass.Bypass]       = new(bypassRegistry)
	resolverReg  reg.Registry[resolver.Resolver]   = new(resolverRegistry)
	hostsReg     reg.Registry[hosts.HostMapper]    = new(hostsRegistry)
	recorderReg  reg.Registry[recorder.Recorder]   = new(recorderRegistry)
	rewriterReg  reg.Registry[rewriter.Rewriter]   = new(rewriterRegistry)

	trafficLimiterReg reg.Registry[traffic.TrafficLimiter] = new(trafficLimiterRegistry)
	connLimiterReg    reg.Registry[conn.ConnLimiter]       = new(connLimiterRegistry)
	rateLimiterReg    reg.Registry[rate.RateLimiter]       = new(rateLimiterRegistry)
	quotaLimiterReg   reg.Registry[*quota.Limiter]         = new(quotaLimiterRegistry)

	ingressReg  reg.Registry[ingress.Ingress]   = new(ingressRegistry)
	routerReg   reg.Registry[router.Router]     = new(routerRegistry)
	sdReg       reg.Registry[sd.SD]             = new(sdRegistry)
	observerReg reg.Registry[observer.Observer] = new(observerRegistry)

	loggerReg reg.Registry[logger.Logger] = new(loggerRegistry)
)

// registry is a sync.Map-backed generic named registry. It implements the
// core Registry[T] interface and is embedded by every typed registry struct.
type registry[T any] struct {
	m sync.Map
}

// Register stores v under name. It returns ErrDup if name is already
// registered. Empty names are silently ignored.
func (r *registry[T]) Register(name string, v T) error {
	if name == "" {
		return nil
	}
	if _, loaded := r.m.LoadOrStore(name, v); loaded {
		return ErrDup
	}

	return nil
}

// Unregister removes the value registered under name. If the value
// implements io.Closer, Close is called before removal; close errors
// are logged but do not prevent deletion.
func (r *registry[T]) Unregister(name string) {
	if v, ok := r.m.Load(name); ok {
		if closer, ok := v.(io.Closer); ok {
			if err := closer.Close(); err != nil {
				logger.Default().Errorf("registry: close %s: %v", name, err)
			}
		}
		r.m.Delete(name)
	}
}

// IsRegistered reports whether a value is registered under name.
func (r *registry[T]) IsRegistered(name string) bool {
	_, ok := r.m.Load(name)
	return ok
}

// Get returns the value registered under name, or the zero value of T
// if name is empty or not registered.
func (r *registry[T]) Get(name string) (t T) {
	if name == "" {
		return
	}
	v, _ := r.m.Load(name)
	t, _ = v.(T)
	return
}

// GetAll returns a snapshot of all registered name-to-value mappings.
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

// ListenerRegistry returns the global registry of listener factory functions.
func ListenerRegistry() reg.Registry[NewListener] {
	return listenerReg
}

// HandlerRegistry returns the global registry of handler factory functions.
func HandlerRegistry() reg.Registry[NewHandler] {
	return handlerReg
}

// DialerRegistry returns the global registry of dialer factory functions.
func DialerRegistry() reg.Registry[NewDialer] {
	return dialerReg
}

// ConnectorRegistry returns the global registry of connector factory functions.
func ConnectorRegistry() reg.Registry[NewConnector] {
	return connectorReg
}

// ServiceRegistry returns the global registry of service instances.
func ServiceRegistry() reg.Registry[service.Service] {
	return serviceReg
}

// ChainRegistry returns the global registry of chain instances.
func ChainRegistry() reg.Registry[chain.Chainer] {
	return chainReg
}

// HopRegistry returns the global registry of hop instances.
func HopRegistry() reg.Registry[hop.Hop] {
	return hopReg
}

// AutherRegistry returns the global registry of authenticator instances.
func AutherRegistry() reg.Registry[auth.Authenticator] {
	return autherReg
}

// AdmissionRegistry returns the global registry of admission instances.
func AdmissionRegistry() reg.Registry[admission.Admission] {
	return admissionReg
}

// BypassRegistry returns the global registry of bypass instances.
func BypassRegistry() reg.Registry[bypass.Bypass] {
	return bypassReg
}

// ResolverRegistry returns the global registry of resolver instances.
func ResolverRegistry() reg.Registry[resolver.Resolver] {
	return resolverReg
}

// HostsRegistry returns the global registry of host mapper instances.
func HostsRegistry() reg.Registry[hosts.HostMapper] {
	return hostsReg
}

// RecorderRegistry returns the global registry of recorder instances.
func RecorderRegistry() reg.Registry[recorder.Recorder] {
	return recorderReg
}

// RewriterRegistry returns the global registry of rewriter instances.
func RewriterRegistry() reg.Registry[rewriter.Rewriter] {
	return rewriterReg
}

// TrafficLimiterRegistry returns the global registry of traffic limiter instances.
func TrafficLimiterRegistry() reg.Registry[traffic.TrafficLimiter] {
	return trafficLimiterReg
}

// ConnLimiterRegistry returns the global registry of connection limiter instances.
func ConnLimiterRegistry() reg.Registry[conn.ConnLimiter] {
	return connLimiterReg
}

// RateLimiterRegistry returns the global registry of rate limiter instances.
func RateLimiterRegistry() reg.Registry[rate.RateLimiter] {
	return rateLimiterReg
}

// QuotaLimiterRegistry returns the global registry of quota limiter instances.
func QuotaLimiterRegistry() reg.Registry[*quota.Limiter] {
	return quotaLimiterReg
}

// IngressRegistry returns the global registry of ingress instances.
func IngressRegistry() reg.Registry[ingress.Ingress] {
	return ingressReg
}

// RouterRegistry returns the global registry of router instances.
func RouterRegistry() reg.Registry[router.Router] {
	return routerReg
}

// SDRegistry returns the global registry of service discovery instances.
func SDRegistry() reg.Registry[sd.SD] {
	return sdReg
}

// ObserverRegistry returns the global registry of observer instances.
func ObserverRegistry() reg.Registry[observer.Observer] {
	return observerReg
}

// LoggerRegistry returns the global registry of logger instances.
func LoggerRegistry() reg.Registry[logger.Logger] {
	return loggerReg
}
