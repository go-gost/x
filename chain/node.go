package chain

import (
	"context"
	"time"

	"github.com/go-gost/core/chain"
	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/probe"
)

// StartNodeProbe starts a background goroutine that periodically probes the
// node's transport. On success the node's marker is reset; on failure the
// marker is incremented. cfg may be nil (no-op).
func StartNodeProbe(node *chain.Node, cfg *chain.ProbeConfig, log logger.Logger) {
	if cfg == nil {
		return
	}
	if cfg.Addr == "" && cfg.Type != chain.ProbeTypeCmd {
		return
	}
	if cfg.Type == chain.ProbeTypeCmd && cfg.Command == "" {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	node.SetProbeCancel(cancel)
	go runNodeProbe(ctx, node, cfg, log)
}

func runNodeProbe(ctx context.Context, node *chain.Node, cfg *chain.ProbeConfig, log logger.Logger) {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	probeNode(node, cfg, log) // first probe immediately
	for {
		select {
		case <-ticker.C:
			probeNode(node, cfg, log)
		case <-ctx.Done():
			return
		}
	}
}

func probeNode(node *chain.Node, cfg *chain.ProbeConfig, log logger.Logger) {
	// cmd probe runs a shell command directly — no transport connection needed.
	if cfg.Type == chain.ProbeTypeCmd {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		start := time.Now()
		err := (&probe.CmdProber{Command: cfg.Command, Timeout: timeout}).Probe()
		latency := time.Since(start)
		if err != nil {
			recordProbe(node, false, latency, err.Error(), log)
		} else {
			recordProbe(node, true, latency, "", log)
		}
		return
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	tr := node.Options().Transport
	conn, err := tr.Dial(ctx, node.Addr)
	if err != nil {
		recordProbe(node, false, time.Since(start), err.Error(), log)
		return
	}

	if hc, err2 := tr.Handshake(ctx, conn); err2 == nil {
		conn = hc
	} else {
		conn.Close()
		recordProbe(node, false, time.Since(start), err2.Error(), log)
		return
	}

	latency := time.Since(start)
	if cfg.Type == chain.ProbeTypeHTTP {
		err = probe.NewHTTPProber(cfg).Probe(conn)
		conn.Close()
		if err != nil {
			recordProbe(node, false, latency, err.Error(), log)
			return
		}
	} else {
		conn.Close()
	}

	recordProbe(node, true, latency, "", log)
}

func recordProbe(node *chain.Node, success bool, latency time.Duration, errStr string, log logger.Logger) {
	result := &chain.ProbeResult{
		Success:   success,
		Latency:   latency,
		Error:     errStr,
		Timestamp: time.Now(),
	}
	node.SetProbeResult(result)

	if success {
		node.Marker().Reset()
	} else {
		node.Marker().Mark()
	}

	log.Debugf("node probe %s: success=%v latency=%v err=%s", node.Name, success, latency, errStr)
}
