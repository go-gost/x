package recorder_test

import (
	"context"
	"testing"
	"time"

	"github.com/go-gost/x/dashboard"
	"github.com/go-gost/x/recorder"
)

func TestFinishFeedsDashboardRing(t *testing.T) {
	dashboard.ResetState()
	dashboard.Enable(true)
	defer func() { dashboard.Enable(false) }()

	before := dashboard.Default().Connections(0, "", "")
	if len(before) != 0 {
		t.Fatalf("ring not empty before finish: %d", len(before))
	}

	sess := recorder.NewSessionRecorder(nil, recorder.SessionRecorderOptions{})
	s := sess.NewSession(context.Background(), nil)
	if err := s.Finish(context.Background(), recorder.HandlerRecorderObject{
		Time:       time.Now(),
		Service:    "svc-test",
		RemoteAddr: "10.0.0.7:9090",
		InputBytes: 123,
		Err:        "dial failed",
	}); err != nil {
		t.Fatalf("finish: %v", err)
	}

	got := dashboard.Default().Connections(0, "", "")
	if len(got) != 1 {
		t.Fatalf("ring len = %d, want 1; records=%+v", len(got), got)
	}
	found := false
	for _, r := range got {
		if r.Service == "svc-test" && r.BytesIn == 123 && r.Err == "dial failed" && r.RemoteAddr == "10.0.0.7:9090" {
			found = true
		}
	}
	if !found {
		t.Fatalf("connection not recorded: %+v", got)
	}
}
