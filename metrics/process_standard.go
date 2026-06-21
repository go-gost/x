//go:build linux || windows

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// registerProcessCollector registers the standard prometheus ProcessCollector
// which uses procfs on Linux and Win32 syscalls on Windows.
func registerProcessCollector(reg *prometheus.Registry) {
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
}
