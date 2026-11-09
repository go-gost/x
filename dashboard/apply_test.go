package dashboard

import (
	"testing"

	"github.com/go-gost/x/config"
)

func TestApplyStartsAndStopsReporter(t *testing.T) {
	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: true}})
	t.Cleanup(func() { Apply(nil) })

	if !reporterActive() {
		t.Fatal("reporter not started")
	}

	Apply(&config.Config{Dashboard: &config.DashboardConfig{Enabled: false}})
	if reporterActive() {
		t.Fatal("reporter not stopped")
	}
}
