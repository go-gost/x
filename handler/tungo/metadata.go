package tungo

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

const (
	defaultBufferSize = 4096
)

type metadata struct {
	udpTimeout    time.Duration
	udpBufferSize int

	sniffing                bool
	sniffingUDP             bool
	sniffingTimeout         time.Duration
	sniffingResponseTimeout time.Duration
	sniffingFallback        bool

	observerPeriod       time.Duration
	observerResetTraffic bool

	limiterRefreshInterval time.Duration
	limiterCleanupInterval time.Duration

	multicastGroups []netip.Addr

	ipv6 bool

	tcpSendBufferSize        int
	tcpReceiveBufferSize     int
	tcpModerateReceiveBuffer bool
}

func (h *tungoHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.udpTimeout = mdutil.GetDuration(md, "udpTimeout", "tungo.udpTimeout")
	h.md.udpBufferSize = mdutil.GetInt(md, "udp.bufferSize", "udpBufferSize")

	h.md.sniffing = mdutil.GetBool(md, "sniffing")
	h.md.sniffingUDP = mdutil.GetBool(md, "sniffing.udp")
	h.md.sniffingTimeout = mdutil.GetDuration(md, "sniffing.timeout")
	h.md.sniffingResponseTimeout = mdutil.GetDuration(md, "sniffing.responseTimeout")
	h.md.sniffingFallback = mdutil.GetBool(md, "sniffing.fallback")

	h.md.observerPeriod = mdutil.GetDuration(md, "observePeriod", "observer.period", "observer.observePeriod")
	if h.md.observerPeriod == 0 {
		h.md.observerPeriod = 5 * time.Second
	}
	if h.md.observerPeriod < time.Second {
		h.md.observerPeriod = time.Second
	}
	h.md.observerResetTraffic = mdutil.GetBool(md, "observer.resetTraffic")

	h.md.limiterRefreshInterval = mdutil.GetDuration(md, "limiter.refreshInterval")
	h.md.limiterCleanupInterval = mdutil.GetDuration(md, "limiter.cleanupInterval")

	for _, v := range strings.Split(mdutil.GetString(md, "multicastGroups", "tungo.multicastGroups"), ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return err
		}
		if !addr.IsMulticast() {
			return fmt.Errorf("invalid multicast IP: %s", addr)
		}
		h.md.multicastGroups = append(h.md.multicastGroups, addr)
	}

	h.md.ipv6 = mdutil.GetBool(md, "ipv6")

	h.md.tcpSendBufferSize = mdutil.GetInt(md, "tcpSendBufferSize", "tungo.tcpSendBufferSize")
	h.md.tcpReceiveBufferSize = mdutil.GetInt(md, "tcpReceiveBufferSize", "tungo.tcpReceiveBufferSize")
	h.md.tcpModerateReceiveBuffer = mdutil.GetBool(md, "tcpModerateReceiveBuffer", "tungo.tcpModerateReceiveBuffer")

	return
}
