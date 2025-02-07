package ip

import (
	"fmt"

	"github.com/songgao/water/waterutil"
)

var prots = map[waterutil.IPProtocol]string{
	waterutil.HOPOPT:     "HOPOPT",
	waterutil.ICMP:       "ICMP",
	waterutil.IGMP:       "IGMP",
	waterutil.GGP:        "GGP",
	waterutil.TCP:        "TCP",
	waterutil.UDP:        "UDP",
	waterutil.IPv6_Route: "IPv6-Route",
	waterutil.IPv6_Frag:  "IPv6-Frag",
	waterutil.IPv6_ICMP:  "IPv6-ICMP",
}

func Protocol(p waterutil.IPProtocol) string {
	if v, ok := prots[p]; ok {
		return v
	}
	return fmt.Sprintf("unknown(%d)", p)
}
