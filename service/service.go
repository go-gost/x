package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metrics"
	"github.com/go-gost/core/observer"
	"github.com/go-gost/core/observer/stats"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/service"
	xctx "github.com/go-gost/x/ctx"
	xmetrics "github.com/go-gost/x/metrics"
	xstats "github.com/go-gost/x/observer/stats"
	"github.com/google/shlex"
	"github.com/rs/xid"
)

type options struct {
	admission      admission.Admission
	recorders      []recorder.RecorderObject
	preUp          []string
	postUp         []string
	preDown        []string
	postDown       []string
	stats          stats.Stats
	observer       observer.Observer
	observerPeriod time.Duration
	logger         logger.Logger
}

type Option func(opts *options)

func AdmissionOption(admission admission.Admission) Option {
	return func(opts *options) {
		opts.admission = admission
	}
}

func RecordersOption(recorders ...recorder.RecorderObject) Option {
	return func(opts *options) {
		opts.recorders = recorders
	}
}

func PreUpOption(cmds []string) Option {
	return func(opts *options) {
		opts.preUp = cmds
	}
}

func PreDownOption(cmds []string) Option {
	return func(opts *options) {
		opts.preDown = cmds
	}
}

func PostUpOption(cmds []string) Option {
	return func(opts *options) {
		opts.postUp = cmds
	}
}

func PostDownOption(cmds []string) Option {
	return func(opts *options) {
		opts.postDown = cmds
	}
}

func StatsOption(stats stats.Stats) Option {
	return func(opts *options) {
		opts.stats = stats
	}
}

func ObserverOption(observer observer.Observer) Option {
	return func(opts *options) {
		opts.observer = observer
	}
}

func ObserverPeriodOption(period time.Duration) Option {
	return func(opts *options) {
		opts.observerPeriod = period
	}
}

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type defaultService struct {
	name     string
	listener listener.Listener
	handler  handler.Handler
	status   *Status
	options  options
}

func NewService(name string, ln listener.Listener, h handler.Handler, opts ...Option) service.Service {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	s := &defaultService{
		name:     name,
		listener: ln,
		handler:  h,
		options:  options,
		status: &Status{
			createTime: time.Now(),
			events:     make([]Event, 0, MaxEventSize),
			stats:      options.stats,
		},
	}
	s.setState(StateRunning)

	s.execCmds("pre-up", s.options.preUp)

	return s
}

func (s *defaultService) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *defaultService) Serve() error {
	s.execCmds("post-up", s.options.postUp)
	s.setState(StateReady)
	s.status.addEvent(Event{
		Time:    time.Now(),
		Message: fmt.Sprintf("service %s is listening on %s", s.name, s.listener.Addr()),
	})

	gctx, cancel := context.WithCancel(context.Background())

	defer cancel()

	if s.status.Stats() != nil {
		go s.observeStats(gctx)
	}

	if v := xmetrics.GetGauge(
		xmetrics.MetricServicesGauge,
		metrics.Labels{}); v != nil {
		v.Inc()
		defer v.Dec()
	}

	log := s.options.logger

	var wg sync.WaitGroup
	defer wg.Wait()

	var tempDelay time.Duration
	for {
		conn, e := s.listener.Accept()
		if e != nil {
			if _, ok := e.(*listener.AcceptError); ok {
				tempDelay = 0
			}

			// TODO: remove Temporary checking
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 1 * time.Second
				} else {
					tempDelay *= 2
				}
				if max := 5 * time.Second; tempDelay > max {
					tempDelay = max
				}

				s.setState(StateFailed)

				log.Warnf("accept: %v, retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			s.setState(StateClosed)

			if !errors.Is(e, net.ErrClosed) {
				log.Errorf("accept: %v", e)
			}

			log.Debugf("service %s exited!", s.name)

			return e
		}

		if tempDelay > 0 {
			tempDelay = 0
			s.setState(StateReady)
		}

		ctx := gctx
		if cv, ok := conn.(xctx.Context); ok {
			if v := cv.Context(); v != nil {
				ctx = v
			}
		}

		sid := xid.New().String()
		ctx = xctx.ContextWithSid(ctx, xctx.Sid(sid))

		log := s.options.logger.WithFields(map[string]any{
			"sid": sid,
		})

		srcAddr := xctx.SrcAddrFromContext(ctx)
		if srcAddr == nil {
			srcAddr = conn.RemoteAddr()
			ctx = xctx.ContextWithSrcAddr(ctx, srcAddr)
		}

		if dstAddr := xctx.DstAddrFromContext(ctx); dstAddr == nil {
			dstAddr = conn.LocalAddr()
			ctx = xctx.ContextWithDstAddr(ctx, dstAddr)
		}

		clientIP := srcAddr.String()
		if h, _, _ := net.SplitHostPort(clientIP); h != "" {
			clientIP = h
		}
		ctx = xctx.ContextWithHash(ctx, &xctx.Hash{Source: clientIP})

		for _, rec := range s.options.recorders {
			if rec.Record == recorder.RecorderServiceClientAddress {
				if err := rec.Recorder.Record(ctx, []byte(clientIP)); err != nil {
					log.Errorf("record %s: %v", rec.Record, err)
				}
				break
			}
		}
		if s.options.admission != nil &&
			!s.options.admission.Admit(ctx, srcAddr.String(), admission.WithService(s.name)) {
			conn.Close()
			log.Debugf("admission: %s is denied", srcAddr)
			continue
		}

		wg.Add(1)

		go func() {
			defer wg.Done()

			if v := xmetrics.GetCounter(xmetrics.MetricServiceRequestsCounter,
				metrics.Labels{"service": s.name, "client": clientIP}); v != nil {
				v.Inc()
			}

			if v := xmetrics.GetGauge(xmetrics.MetricServiceRequestsInFlightGauge,
				metrics.Labels{"service": s.name, "client": clientIP}); v != nil {
				v.Inc()
				defer v.Dec()
			}

			start := time.Now()
			if v := xmetrics.GetObserver(xmetrics.MetricServiceRequestsDurationObserver,
				metrics.Labels{"service": s.name}); v != nil {
				defer func() {
					v.Observe(float64(time.Since(start).Seconds()))
				}()
			}

			if err := s.handler.Handle(ctx, conn); err != nil {
				log.Error(err)
				if v := xmetrics.GetCounter(xmetrics.MetricServiceHandlerErrorsCounter,
					metrics.Labels{"service": s.name, "client": clientIP}); v != nil {
					v.Inc()
				}
				if sts := s.status.stats; sts != nil {
					sts.Add(stats.KindTotalErrs, 1)
				}
			}
		}()
	}
}

func (s *defaultService) Status() *Status {
	return s.status
}

func (s *defaultService) Close() error {
	s.execCmds("pre-down", s.options.preDown)
	defer s.execCmds("post-down", s.options.postDown)

	if closer, ok := s.handler.(io.Closer); ok {
		closer.Close()
	}
	return s.listener.Close()
}

func (s *defaultService) execCmds(phase string, cmds []string) {
	for _, cmd := range cmds {
		cmd := strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		s.options.logger.Info(cmd)

		if err := s.execCmd(cmd); err != nil {
			s.options.logger.Warnf("[%s] %s: %v", phase, cmd, err)
		}
	}
}

func (s *defaultService) execCmd(cmd string) error {
	ss, err := shlex.Split(cmd)
	if err != nil {
		return err
	}
	if len(ss) == 0 {
		return errors.New("invalid command")
	}
	c := exec.Command(ss[0], ss[1:]...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func (s *defaultService) setState(state State) {
	s.status.setState(state)

	msg := fmt.Sprintf("service %s is %s", s.name, state)
	s.status.addEvent(Event{
		Time:    time.Now(),
		Message: msg,
	})

	if obs := s.options.observer; obs != nil {
		obs.Observe(context.Background(), []observer.Event{ServiceEvent{
			Kind:    "service",
			Service: s.name,
			State:   state,
			Msg:     msg,
		}})
	}
}

func (s *defaultService) observeStats(ctx context.Context) {
	if s.options.observer == nil {
		return
	}

	d := s.options.observerPeriod
	if d == 0 {
		d = 5 * time.Second
	}
	if d < time.Second {
		d = 1 * time.Second
	}

	var events []observer.Event

	ticker := time.NewTicker(d)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if len(events) > 0 {
				if err := s.options.observer.Observe(ctx, events); err == nil {
					events = nil
				}
				break
			}

			st := s.status.Stats()
			if st == nil || !st.IsUpdated() {
				break
			}

			evs := []observer.Event{
				xstats.StatsEvent{
					Kind:         "service",
					Service:      s.name,
					TotalConns:   st.Get(stats.KindTotalConns),
					CurrentConns: st.Get(stats.KindCurrentConns),
					InputBytes:   st.Get(stats.KindInputBytes),
					OutputBytes:  st.Get(stats.KindOutputBytes),
					TotalErrs:    st.Get(stats.KindTotalErrs),
				},
			}
			if err := s.options.observer.Observe(ctx, evs); err != nil {
				events = evs
			}

		case <-ctx.Done():
			return
		}
	}
}

type ServiceEvent struct {
	Kind    string
	Service string
	State   State
	Msg     string
}

func (ServiceEvent) Type() observer.EventType {
	return observer.EventStatus
}
