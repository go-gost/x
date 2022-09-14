package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	resolver_util "github.com/go-gost/x/internal/util/resolver"
	"github.com/go-gost/x/registry"
	"github.com/go-gost/x/resolver/exchanger"
	"github.com/miekg/dns"
)

const (
	defaultNameserver = "udp://127.0.0.1:53"
)

func init() {
	registry.HandlerRegistry().Register("dns", NewHandler)
}

type dnsHandler struct {
	group      *chain.NodeGroup
	exchangers map[string]exchanger.Exchanger
	cache      *resolver_util.Cache
	router     *chain.Router
	hosts      hosts.HostMapper
	md         metadata
	options    handler.Options
}

func NewHandler(opts ...handler.Option) handler.Handler {
	options := handler.Options{}
	for _, opt := range opts {
		opt(&options)
	}

	return &dnsHandler{
		options:    options,
		exchangers: make(map[string]exchanger.Exchanger),
	}
}

func (h *dnsHandler) Init(md md.Metadata) (err error) {
	if err = h.parseMetadata(md); err != nil {
		return
	}
	log := h.options.Logger

	h.cache = resolver_util.NewCache().WithLogger(log)

	h.router = h.options.Router
	if h.router == nil {
		h.router = (&chain.Router{}).WithLogger(log)
	}
	h.hosts = h.router.Hosts()

	if h.group == nil {
		h.group = &chain.NodeGroup{}
		for i, addr := range h.md.dns {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			h.group.AddNode(chain.NewNode(fmt.Sprintf("target-%d", i), addr))
		}
	}
	for _, node := range h.group.Nodes() {
		addr := strings.TrimSpace(node.Addr)
		if addr == "" {
			continue
		}
		ex, err := exchanger.NewExchanger(
			addr,
			exchanger.RouterOption(h.router),
			exchanger.TimeoutOption(h.md.timeout),
			exchanger.LoggerOption(log),
		)
		if err != nil {
			log.Warnf("parse %s: %v", addr, err)
			continue
		}
		h.exchangers[node.Name] = ex
	}

	if len(h.exchangers) == 0 {
		ex, err := exchanger.NewExchanger(
			defaultNameserver,
			exchanger.RouterOption(h.router),
			exchanger.TimeoutOption(h.md.timeout),
			exchanger.LoggerOption(log),
		)
		log.Warnf("resolver not found, default to %s", defaultNameserver)
		if err != nil {
			return err
		}
		h.exchangers["default"] = ex
	}

	return
}

// Forward implements handler.Forwarder.
func (h *dnsHandler) Forward(group *chain.NodeGroup) {
	h.group = group
}

func (h *dnsHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) error {
	defer conn.Close()

	start := time.Now()
	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())
	defer func() {
		log.WithFields(map[string]any{
			"duration": time.Since(start),
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())
	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return nil
	}

	b := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(b)

	n, err := conn.Read(*b)
	if err != nil {
		log.Error(err)
		return err
	}

	reply, err := h.exchange(ctx, (*b)[:n], log)
	if err != nil {
		return err
	}
	defer bufpool.Put(&reply)

	if _, err = conn.Write(reply); err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func (h *dnsHandler) checkRateLimit(addr net.Addr) bool {
	if h.options.RateLimiter == nil {
		return true
	}
	host, _, _ := net.SplitHostPort(addr.String())
	if limiter := h.options.RateLimiter.Limiter(host); limiter != nil {
		return limiter.Allow(1)
	}

	return true
}

func (h *dnsHandler) exchange(ctx context.Context, msg []byte, log logger.Logger) ([]byte, error) {
	mq := dns.Msg{}
	if err := mq.Unpack(msg); err != nil {
		log.Error(err)
		return nil, err
	}

	if len(mq.Question) == 0 {
		return nil, errors.New("msg: empty question")
	}

	resolver_util.AddSubnetOpt(&mq, h.md.clientIP)

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Trace(mq.String())
	}

	var mr *dns.Msg
	if log.IsLevelEnabled(logger.TraceLevel) {
		defer func() {
			if mr != nil {
				log.Trace(mr.String())
			}
		}()
	}

	if h.options.Bypass != nil && mq.Question[0].Qclass == dns.ClassINET {
		if h.options.Bypass.Contains(strings.Trim(mq.Question[0].Name, ".")) {
			log.Debug("bypass: ", mq.Question[0].Name)
			mr = (&dns.Msg{}).SetReply(&mq)
			b := bufpool.Get(h.md.bufferSize)
			return mr.PackBuffer(*b)
		}
	}

	mr = h.lookupHosts(&mq, log)
	if mr != nil {
		b := bufpool.Get(h.md.bufferSize)
		return mr.PackBuffer(*b)
	}

	// only cache for single question message.
	if len(mq.Question) == 1 {
		key := resolver_util.NewCacheKey(&mq.Question[0])
		mr = h.cache.Load(key)
		if mr != nil {
			log.Debugf("exchange message %d (cached): %s", mq.Id, mq.Question[0].String())
			mr.Id = mq.Id

			b := bufpool.Get(h.md.bufferSize)
			return mr.PackBuffer(*b)
		}

		defer func() {
			if mr != nil {
				h.cache.Store(key, mr, h.md.ttl)
			}
		}()
	}

	b := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(b)

	query, err := mq.PackBuffer(*b)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	ex := h.selectExchanger(ctx, strings.Trim(mq.Question[0].Name, "."))
	if ex == nil {
		err := fmt.Errorf("exchange not found for %s", mq.Question[0].Name)
		log.Error(err)
		return nil, err
	}

	reply, err := ex.Exchange(ctx, query)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	mr = &dns.Msg{}
	if err = mr.Unpack(reply); err != nil {
		log.Error(err)
		return nil, err
	}

	return reply, nil
}

// lookup host mapper
func (h *dnsHandler) lookupHosts(r *dns.Msg, log logger.Logger) (m *dns.Msg) {
	if h.hosts == nil ||
		r.Question[0].Qclass != dns.ClassINET ||
		(r.Question[0].Qtype != dns.TypeA && r.Question[0].Qtype != dns.TypeAAAA) {
		return nil
	}

	m = &dns.Msg{}
	m.SetReply(r)

	host := strings.TrimSuffix(r.Question[0].Name, ".")

	switch r.Question[0].Qtype {
	case dns.TypeA:
		ips, _ := h.hosts.Lookup("ip4", host)
		if len(ips) == 0 {
			return nil
		}
		log.Debugf("hit host mapper: %s -> %s", host, ips)

		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s IN A %s\n", r.Question[0].Name, ip.String()))
			if err != nil {
				log.Error(err)
				return nil
			}
			m.Answer = append(m.Answer, rr)
		}

	case dns.TypeAAAA:
		ips, _ := h.hosts.Lookup("ip6", host)
		if len(ips) == 0 {
			return nil
		}
		log.Debugf("hit host mapper: %s -> %s", host, ips)

		for _, ip := range ips {
			rr, err := dns.NewRR(fmt.Sprintf("%s IN AAAA %s\n", r.Question[0].Name, ip.String()))
			if err != nil {
				log.Error(err)
				return nil
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	return
}

func (h *dnsHandler) selectExchanger(ctx context.Context, addr string) exchanger.Exchanger {
	if h.group == nil {
		return nil
	}
	node := h.group.FilterAddr(addr).Next(ctx)
	if node == nil {
		return nil
	}

	return h.exchangers[node.Name]
}
