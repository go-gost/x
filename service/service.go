package service

import (
	"context"
	"hash/crc32"
	"net"
	"time"

	"github.com/go-gost/core/admission"
	"github.com/go-gost/core/handler"
	"github.com/go-gost/core/listener"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/core/metrics"
	"github.com/go-gost/core/recorder"
	"github.com/go-gost/core/service"
	sx "github.com/go-gost/x/internal/util/selector"
	xmetrics "github.com/go-gost/x/metrics"
)

type options struct {
	admission admission.Admission
	recorders []recorder.RecorderObject
	logger    logger.Logger
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

func LoggerOption(logger logger.Logger) Option {
	return func(opts *options) {
		opts.logger = logger
	}
}

type defaultService struct {
	name     string
	listener listener.Listener
	handler  handler.Handler
	options  options
}

func NewService(name string, ln listener.Listener, h handler.Handler, opts ...Option) service.Service {
	var options options
	for _, opt := range opts {
		opt(&options)
	}
	return &defaultService{
		name:     name,
		listener: ln,
		handler:  h,
		options:  options,
	}
}

func (s *defaultService) Addr() net.Addr {
	return s.listener.Addr()
}

func (s *defaultService) Close() error {
	return s.listener.Close()
}

func (s *defaultService) Serve() error {
	if v := xmetrics.GetGauge(
		xmetrics.MetricServicesGauge,
		metrics.Labels{}); v != nil {
		v.Inc()
		defer v.Dec()
	}

	var tempDelay time.Duration
	for {
		conn, e := s.listener.Accept()
		if e != nil {
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
				s.options.logger.Warnf("accept: %v, retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			s.options.logger.Errorf("accept: %v", e)
			return e
		}
		tempDelay = 0

		for _, rec := range s.options.recorders {
			host := conn.RemoteAddr().String()
			if h, _, _ := net.SplitHostPort(host); h != "" {
				host = h
			}
			if rec.Record == recorder.RecorderServiceClientAddress {
				if err := rec.Recorder.Record(context.Background(), []byte(host)); err != nil {
					s.options.logger.Errorf("record %s: %v", rec.Record, err)
				}
			}
		}
		if s.options.admission != nil &&
			!s.options.admission.Admit(conn.RemoteAddr().String()) {
			conn.Close()
			s.options.logger.Debugf("admission: %s is denied", conn.RemoteAddr())
			continue
		}

		go func() {
			if v := xmetrics.GetCounter(xmetrics.MetricServiceRequestsCounter,
				metrics.Labels{"service": s.name}); v != nil {
				v.Inc()
			}

			if v := xmetrics.GetGauge(xmetrics.MetricServiceRequestsInFlightGauge,
				metrics.Labels{"service": s.name}); v != nil {
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

			ctx := sx.ContextWithHash(context.Background(), &sx.Hash{
				Source: conn.RemoteAddr().String(),
				Value:  ipHash(conn.RemoteAddr()),
			})

			if err := s.handler.Handle(ctx, conn); err != nil {
				s.options.logger.Error(err)
				if v := xmetrics.GetCounter(xmetrics.MetricServiceHandlerErrorsCounter,
					metrics.Labels{"service": s.name}); v != nil {
					v.Inc()
				}
			}
		}()
	}
}

func ipHash(addr net.Addr) uint64 {
	if addr == nil {
		return 0
	}

	host, _, _ := net.SplitHostPort(addr.String())
	if ip := net.ParseIP(host); ip != nil {
		return uint64(crc32.ChecksumIEEE(ip.To16()))
	}
	return 0
}
