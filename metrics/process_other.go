//go:build !linux && !windows

package metrics

import (
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	psutil "github.com/shirou/gopsutil/v3/process"
)

// gopsutilProcessCollector implements prometheus.Collector using gopsutil/v3
// for cross-platform process metrics on non-Linux, non-Windows systems
// (FreeBSD, Darwin, etc.) where procfs is unavailable.
type gopsutilProcessCollector struct {
	pidFn        func() (int, error)
	cpuTotal     *prometheus.Desc
	openFDs      *prometheus.Desc
	maxFDs       *prometheus.Desc
	vsize        *prometheus.Desc
	maxVsize     *prometheus.Desc
	rss          *prometheus.Desc
	startTime    *prometheus.Desc
	reportErrors bool
}

func getPID() (int, error) { return os.Getpid(), nil }

func newGopsutilProcessCollector() prometheus.Collector {
	return &gopsutilProcessCollector{
		pidFn: getPID,
		cpuTotal: prometheus.NewDesc(
			"process_cpu_seconds_total",
			"Total user and system CPU time spent in seconds.",
			nil, nil,
		),
		openFDs: prometheus.NewDesc(
			"process_open_fds",
			"Number of open file descriptors.",
			nil, nil,
		),
		maxFDs: prometheus.NewDesc(
			"process_max_fds",
			"Maximum number of open file descriptors.",
			nil, nil,
		),
		vsize: prometheus.NewDesc(
			"process_virtual_memory_bytes",
			"Virtual memory size in bytes.",
			nil, nil,
		),
		maxVsize: prometheus.NewDesc(
			"process_virtual_memory_max_bytes",
			"Maximum amount of virtual memory available in bytes.",
			nil, nil,
		),
		rss: prometheus.NewDesc(
			"process_resident_memory_bytes",
			"Resident memory size in bytes.",
			nil, nil,
		),
		startTime: prometheus.NewDesc(
			"process_start_time_seconds",
			"Start time of the process since unix epoch in seconds.",
			nil, nil,
		),
		reportErrors: false,
	}
}

func (c *gopsutilProcessCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.cpuTotal
	ch <- c.openFDs
	ch <- c.maxFDs
	ch <- c.vsize
	ch <- c.maxVsize
	ch <- c.rss
	ch <- c.startTime
}

func (c *gopsutilProcessCollector) Collect(ch chan<- prometheus.Metric) {
	pid, err := c.pidFn()
	if err != nil {
		c.reportError(ch, nil, err)
		return
	}

	p, err := psutil.NewProcess(int32(pid))
	if err != nil {
		c.reportError(ch, nil, err)
		return
	}

	// Memory metrics: RSS (resident) and VMS (virtual).
	if mem, err := p.MemoryInfo(); err == nil {
		ch <- prometheus.MustNewConstMetric(c.rss, prometheus.GaugeValue, float64(mem.RSS))
		ch <- prometheus.MustNewConstMetric(c.vsize, prometheus.GaugeValue, float64(mem.VMS))
	} else {
		c.reportError(ch, c.rss, err)
	}

	// CPU time.
	if times, err := p.Times(); err == nil {
		cpuSeconds := times.User + times.System
		ch <- prometheus.MustNewConstMetric(c.cpuTotal, prometheus.CounterValue, cpuSeconds)
	} else {
		c.reportError(ch, c.cpuTotal, err)
	}

	// Open file descriptors.
	if fds, err := p.NumFDs(); err == nil {
		ch <- prometheus.MustNewConstMetric(c.openFDs, prometheus.GaugeValue, float64(fds))
	} else {
		c.reportError(ch, c.openFDs, err)
	}

	// Max file descriptors — not reliably available via gopsutil on all platforms.
	// Try RLIMIT_NOFILE via gopsutil's RlimitUsage.
	if rlimits, err := p.RlimitUsage(false); err == nil && len(rlimits) > 0 {
		for _, rl := range rlimits {
			switch rl.Resource {
			case psutil.RLIMIT_NOFILE:
				ch <- prometheus.MustNewConstMetric(c.maxFDs, prometheus.GaugeValue, float64(rl.Hard))
			case psutil.RLIMIT_AS:
				ch <- prometheus.MustNewConstMetric(c.maxVsize, prometheus.GaugeValue, float64(rl.Hard))
			}
		}
	}

	// Process start time.
	if ct, err := p.CreateTime(); err == nil {
		createTime := time.Unix(ct/1000, (ct%1000)*1e6)
		ch <- prometheus.MustNewConstMetric(c.startTime, prometheus.GaugeValue, float64(createTime.Unix()))
	} else {
		c.reportError(ch, c.startTime, err)
	}
}

func (c *gopsutilProcessCollector) reportError(ch chan<- prometheus.Metric, desc *prometheus.Desc, err error) {
	if !c.reportErrors {
		return
	}
	if desc == nil {
		desc = prometheus.NewInvalidDesc(err)
	}
	ch <- prometheus.NewInvalidMetric(desc, err)
}

// registerProcessCollector registers a gopsutil-based process metrics collector
// for platforms where procfs is unavailable.
func registerProcessCollector(reg *prometheus.Registry) {
	reg.MustRegister(newGopsutilProcessCollector())
}
