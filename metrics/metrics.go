package metrics

import (
	"sync/atomic"

	"github.com/go-gost/core/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const (
	// Number of services. Labels: host.
	MetricServicesGauge metrics.MetricName = "gost_services"
	// Total service requests. Labels: host, service, client.
	MetricServiceRequestsCounter metrics.MetricName = "gost_service_requests_total"
	// Number of in-flight requests. Labels: host, service, client.
	MetricServiceRequestsInFlightGauge metrics.MetricName = "gost_service_requests_in_flight"
	// Request duration histogram. Labels: host, service.
	MetricServiceRequestsDurationObserver metrics.MetricName = "gost_service_request_duration_seconds"
	// Total service input data transfer size in bytes. Labels: host, service, client.
	MetricServiceTransferInputBytesCounter metrics.MetricName = "gost_service_transfer_input_bytes_total"
	// Total service output data transfer size in bytes. Labels: host, service, client.
	MetricServiceTransferOutputBytesCounter metrics.MetricName = "gost_service_transfer_output_bytes_total"
	// Chain node connect duration histogram. Labels: host, chain, node.
	MetricNodeConnectDurationObserver metrics.MetricName = "gost_chain_node_connect_duration_seconds"
	// Total service handler errors. Labels: host, service, client.
	MetricServiceHandlerErrorsCounter metrics.MetricName = "gost_service_handler_errors_total"
	// Total chain connect errors. Labels: host, chain, node.
	MetricChainErrorsCounter metrics.MetricName = "gost_chain_errors_total"
	// Total recorder records. Labels: host, recorder.
	MetricRecorderRecordsCounter metrics.MetricName = "gost_recorder_records_total"
)

var (
	defaultMetrics  metrics.Metrics
	defaultRegistry *prometheus.Registry
	enabled         atomic.Bool
)

func init() {
	defaultRegistry = prometheus.NewRegistry()

	// Register Go and process collectors on our custom registry so the metrics
	// endpoint is self-contained. The process collector is platform-specific:
	// Linux/Windows use the standard procfs/Win32-based collector; all other
	// platforms (FreeBSD, Darwin, etc.) use a gopsutil-based collector.
	defaultRegistry.MustRegister(collectors.NewGoCollector())
	registerProcessCollector(defaultRegistry)

	defaultMetrics = NewMetrics(defaultRegistry)
}

// Registry returns the custom Prometheus registry that holds all GOST metrics
// plus the Go and process collectors. The metrics HTTP endpoint should serve
// from this registry rather than prometheus.DefaultGatherer.
func Registry() *prometheus.Registry {
	return defaultRegistry
}

// Enable enables or disables metrics collection globally. When disabled, all
// GetCounter, GetGauge, and GetObserver calls return noop implementations.
func Enable(b bool) {
	enabled.Store(b)
}

// IsEnabled reports whether metrics collection is enabled.
func IsEnabled() bool {
	return enabled.Load()
}

// GetCounter returns a Counter for the given name and labels. When metrics are
// disabled, a noop implementation is returned.
func GetCounter(name metrics.MetricName, labels metrics.Labels) metrics.Counter {
	if IsEnabled() {
		return defaultMetrics.Counter(name, labels)
	}
	return noop.Counter(name, labels)
}

// GetGauge returns a Gauge for the given name and labels. When metrics are
// disabled, a noop implementation is returned.
func GetGauge(name metrics.MetricName, labels metrics.Labels) metrics.Gauge {
	if IsEnabled() {
		return defaultMetrics.Gauge(name, labels)
	}
	return noop.Gauge(name, labels)
}

// GetObserver returns an Observer for the given name and labels. When metrics are
// disabled, a noop implementation is returned.
func GetObserver(name metrics.MetricName, labels metrics.Labels) metrics.Observer {
	if IsEnabled() {
		return defaultMetrics.Observer(name, labels)
	}
	return noop.Observer(name, labels)
}
