package tun

import (
	"testing"

	xmd "github.com/go-gost/x/metadata"
)

func TestParseMetadataProbeDefaultOff(t *testing.T) {
	h := &tunHandler{}
	if err := h.parseMetadata(xmd.NewMetadata(map[string]any{})); err != nil {
		t.Fatal(err)
	}
	if h.md.probe {
		t.Fatal("probe defaults off")
	}
	if h.md.probeReport != nil {
		t.Fatal("probeReport defaults nil")
	}
}

func TestParseMetadataProbeOn(t *testing.T) {
	called := false
	report := func(sentDelta, ackedDelta uint64) { called = true }
	h := &tunHandler{}
	if err := h.parseMetadata(xmd.NewMetadata(map[string]any{
		"probe":       true,
		"probeReport": report,
	})); err != nil {
		t.Fatal(err)
	}
	if !h.md.probe {
		t.Fatal("probe not enabled")
	}
	if h.md.probeReport == nil {
		t.Fatal("probeReport not plumbed")
	}
	h.md.probeReport(1, 0)
	if !called {
		t.Fatal("probeReport is not the func from metadata")
	}
}

func TestParseMetadataProbeBadReportIgnored(t *testing.T) {
	h := &tunHandler{}
	if err := h.parseMetadata(xmd.NewMetadata(map[string]any{
		"probe":       true,
		"probeReport": "not-a-func",
	})); err != nil {
		t.Fatal(err)
	}
	if !h.md.probe {
		t.Fatal("probe not enabled")
	}
	if h.md.probeReport != nil {
		t.Fatal("bad probeReport must stay nil, not panic")
	}
}
