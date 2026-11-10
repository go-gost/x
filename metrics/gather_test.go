package metrics

import (
	"testing"

	"github.com/go-gost/core/metrics"
)

func TestGatherFamiliesOnlyRequested(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	GetCounter(MetricChainErrorsCounter, metrics.Labels{"chain": "gather-test", "node": "node-0"}).Inc()
	GetCounter(MetricServiceRequestsCounter, metrics.Labels{"service": "gather-test", "client": "c"}).Inc()

	mfs, err := GatherFamilies(MetricChainErrorsCounter)
	if err != nil {
		t.Fatal(err)
	}
	if len(mfs) != 1 || mfs[0].GetName() != string(MetricChainErrorsCounter) {
		t.Fatalf("families = %v", mfs)
	}
}

func TestGatherFamiliesDeduplicates(t *testing.T) {
	orig := IsEnabled()
	Enable(true)
	defer Enable(orig)

	if _, err := GatherFamilies(MetricChainErrorsCounter, MetricChainErrorsCounter); err != nil {
		t.Fatal(err)
	}
}
