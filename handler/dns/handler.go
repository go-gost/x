package dns

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/common/bufpool"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/hop"
	"github.com/go-gost/core/hosts"
	"github.com/go-gost/core/logger"
	md "github.com/go-gost/core/metadata"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	ctxvalue "github.com/go-gost/x/ctx"
	xhop "github.com/go-gost/x/hop"
	resolver_util "github.com/go-gost/x/internal/util/resolver"
	rate_limiter "github.com/go-gost/x/limiter/rate"
	xstats "github.com/go-gost/x/observer/stats"
	stats_wrapper "github.com/go-gost/x/observer/stats/wrapper"
	xrecorder "github.com/go-gost/x/recorder"
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
	hop        hop.Hop
	exchangers map[string]exchanger.Exchanger
	cache      *resolver_util.Cache
	hostMapper hosts.HostMapper
	md         metadata
	options    handler.Options
	recorder   recorder.RecorderObject
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

	h.hostMapper = h.options.Router.Options().HostMapper

	if h.hop == nil {
		var nodes []*chain.Node
		for i, addr := range h.md.dns {
			nodes = append(nodes, chain.NewNode(fmt.Sprintf("target-%d", i), addr))
		}
		h.hop = xhop.NewHop(
			xhop.NodeOption(nodes...),
			xhop.LoggerOption(log),
		)
	}

	var nodes []*chain.Node
	if nl, ok := h.hop.(hop.NodeList); ok {
		nodes = nl.Nodes()
	}
	for _, node := range nodes {
		addr := strings.TrimSpace(node.Addr)
		if addr == "" {
			continue
		}
		ex, err := exchanger.NewExchanger(
			addr,
			exchanger.RouterOption(h.options.Router),
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
			exchanger.RouterOption(h.options.Router),
			exchanger.TimeoutOption(h.md.timeout),
			exchanger.LoggerOption(log),
		)
		log.Warnf("resolver not found, use default %s", defaultNameserver)
		if err != nil {
			return err
		}
		h.exchangers["default"] = ex
	}

	for _, ro := range h.options.Recorders {
		if ro.Record == xrecorder.RecorderServiceHandler {
			h.recorder = ro
			break
		}
	}

	return
}

// Forward implements handler.Forwarder.
func (h *dnsHandler) Forward(hop hop.Hop) {
	h.hop = hop
}

func (h *dnsHandler) Handle(ctx context.Context, conn net.Conn, opts ...handler.HandleOption) (err error) {
	defer conn.Close()

	start := time.Now()

	ro := &xrecorder.HandlerRecorderObject{
		Service:    h.options.Service,
		Network:    conn.LocalAddr().Network(),
		RemoteAddr: conn.RemoteAddr().String(),
		LocalAddr:  conn.LocalAddr().String(),
		Proto:      "dns",
		Time:       start,
		SID:        string(ctxvalue.SidFromContext(ctx)),
	}

	ro.ClientIP = conn.RemoteAddr().String()
	if clientAddr := ctxvalue.ClientAddrFromContext(ctx); clientAddr != "" {
		ro.ClientIP = string(clientAddr)
	}
	if h, _, _ := net.SplitHostPort(ro.ClientIP); h != "" {
		ro.ClientIP = h
	}

	log := h.options.Logger.WithFields(map[string]any{
		"remote": conn.RemoteAddr().String(),
		"local":  conn.LocalAddr().String(),
		"sid":    ctxvalue.SidFromContext(ctx),
		"client": ro.ClientIP,
	})

	log.Infof("%s <> %s", conn.RemoteAddr(), conn.LocalAddr())

	pStats := xstats.Stats{}
	conn = stats_wrapper.WrapConn(conn, &pStats)

	defer func() {
		ro.Duration = time.Since(start)
		if err != nil {
			ro.Err = err.Error()
		}
		ro.InputBytes = pStats.Get(stats.KindInputBytes)
		ro.OutputBytes = pStats.Get(stats.KindOutputBytes)
		if err := ro.Record(ctx, h.recorder.Recorder); err != nil {
			log.Warnf("recorder: %v", err)
		}

		log.WithFields(map[string]any{
			"duration":    time.Since(start),
			"inputBytes":  ro.InputBytes,
			"outputBytes": ro.OutputBytes,
		}).Infof("%s >< %s", conn.RemoteAddr(), conn.LocalAddr())

	}()

	if !h.checkRateLimit(conn.RemoteAddr()) {
		return rate_limiter.ErrRateLimit
	}

	b := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(b)

	n, err := conn.Read(b)
	if err != nil {
		log.Error(err)
		return err
	}

	reply, err := h.request(ctx, b[:n], ro, log)
	if err != nil {
		return err
	}
	defer bufpool.Put(reply)

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

func (h *dnsHandler) request(ctx context.Context, msg []byte, ro *xrecorder.HandlerRecorderObject, log logger.Logger) ([]byte, error) {
	mq := dns.Msg{}
	if err := mq.Unpack(msg); err != nil {
		log.Error(err)
		return nil, err
	}

	if len(mq.Question) == 0 {
		return nil, errors.New("msg: empty question")
	}

	ro.DNS = &xrecorder.DNSRecorderObject{
		ID:       int(mq.Id),
		Name:     mq.Question[0].Name,
		Class:    dns.Class(mq.Question[0].Qclass).String(),
		Type:     dns.Type(mq.Question[0].Qtype).String(),
		Question: mq.String(),
	}

	resolver_util.AddSubnetOpt(&mq, h.md.clientIP)

	if log.IsLevelEnabled(logger.TraceLevel) {
		log.Trace(mq.String())
	}

	var mr *dns.Msg
	defer func() {
		if mr != nil {
			if log.IsLevelEnabled(logger.TraceLevel) {
				log.Trace(mr.String())
			}

			ro.DNS.Answer = mr.String()
		}
	}()

	if h.options.Bypass != nil && mq.Question[0].Qclass == dns.ClassINET {
		if h.options.Bypass.Contains(context.Background(), "udp", strings.Trim(mq.Question[0].Name, ".")) {
			log.Debug("bypass: ", mq.Question[0].Name)
			mr = (&dns.Msg{}).SetReply(&mq)
			b := bufpool.Get(h.md.bufferSize)
			return mr.PackBuffer(b)
		}
	}

	mr = h.lookupHosts(ctx, &mq, log)
	if mr != nil {
		b := bufpool.Get(h.md.bufferSize)
		return mr.PackBuffer(b)
	}

	// only cache for single question message.
	if len(mq.Question) == 1 {
		var ttl time.Duration
		mr, ttl = h.cache.Load(ctx, resolver_util.NewCacheKey(&mq.Question[0]))
		if mr != nil {
			mr.Id = mq.Id
			if int32(ttl.Seconds()) > 0 {
				ro.DNS.Cached = true

				log.Debugf("message %d (cached): %s", mq.Id, mq.Question[0].String())
				b := bufpool.Get(h.md.bufferSize)
				return mr.PackBuffer(b)
			}
		}
	}

	ex := h.selectExchanger(ctx, strings.Trim(mq.Question[0].Name, "."))
	if ex == nil {
		return nil, fmt.Errorf("exchange not found for %s", mq.Question[0].Name)
	}
	ro.Host = ex.String()

	if mr != nil && h.md.async {
		b := bufpool.Get(h.md.bufferSize)
		reply, err := mr.PackBuffer(b)
		if err != nil {
			return nil, err
		}
		h.cache.RefreshTTL(resolver_util.NewCacheKey(&mq.Question[0]))

		log.Debugf("exchange message %d (async): %s", mq.Id, mq.Question[0].String())
		go h.exchange(ctx, ex, &mq)
		return reply, nil
	}

	log.Debugf("exchange message %d: %s", mq.Id, mq.Question[0].String())

	var buf bytes.Buffer
	mr, err := h.exchange(ctxvalue.ContextWithBuffer(ctx, &buf), ex, &mq)
	ro.Route = buf.String()
	if err != nil {
		return nil, err
	}

	b := bufpool.Get(h.md.bufferSize)
	return mr.PackBuffer(b)
}

func (h *dnsHandler) exchange(ctx context.Context, ex exchanger.Exchanger, mq *dns.Msg) (*dns.Msg, error) {
	b := bufpool.Get(h.md.bufferSize)
	defer bufpool.Put(b)

	query, err := mq.PackBuffer(b)
	if err != nil {
		return nil, err
	}

	reply, err := ex.Exchange(ctx, query)
	if err != nil {
		return nil, err
	}

	mr := &dns.Msg{}
	if err = mr.Unpack(reply); err != nil {
		return nil, err
	}
	if len(mq.Question) == 1 {
		key := resolver_util.NewCacheKey(&mq.Question[0])
		h.cache.Store(ctx, key, mr, h.md.ttl)
	}

	return mr, nil
}

// lookup host mapper
func (h *dnsHandler) lookupHosts(ctx context.Context, r *dns.Msg, log logger.Logger) (m *dns.Msg) {
	if h.hostMapper == nil ||
		r.Question[0].Qclass != dns.ClassINET ||
		(r.Question[0].Qtype != dns.TypeA && r.Question[0].Qtype != dns.TypeAAAA) {
		return nil
	}

	m = &dns.Msg{}
	m.SetReply(r)

	host := strings.TrimSuffix(r.Question[0].Name, ".")

	switch r.Question[0].Qtype {
	case dns.TypeA:
		ips, _ := h.hostMapper.Lookup(ctx, "ip4", host)
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
		ips, _ := h.hostMapper.Lookup(ctx, "ip6", host)
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
	if h.hop == nil {
		return nil
	}
	node := h.hop.Select(ctx, hop.AddrSelectOption(addr))
	if node == nil {
		return nil
	}

	return h.exchangers[node.Name]
}
