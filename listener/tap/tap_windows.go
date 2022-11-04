package tap

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	tap_util "github.com/go-gost/x/internal/util/tap"
	"github.com/songgao/water"
)

func (l *tapListener) createTap() (dev io.ReadWriteCloser, name string, ip net.IP, err error) {
	ip, ipNet, _ := net.ParseCIDR(l.md.config.Net)

	ifce, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID:   "tap0901",
			InterfaceName: l.md.config.Name,
			Network:       l.md.config.Net,
		},
	})
	if err != nil {
		return
	}

	dev = ifce
	name = ifce.Name()

	if ip != nil && ipNet != nil {
		cmd := fmt.Sprintf("netsh interface ip set address name=%s "+
			"source=static addr=%s mask=%s gateway=none",
			ifce.Name(), ip.String(), ipMask(ipNet.Mask))
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
	}

	if err = l.addRoutes(ifce.Name(), l.md.config.Routes...); err != nil {
		return
	}

	return
}

func (l *tapListener) addRoutes(ifName string, routes ...tap_util.Route) error {
	for _, route := range routes {
		l.deleteRoute(ifName, route)

		cmd := fmt.Sprintf("netsh interface ip add route prefix=%s interface=%s store=active",
			route.Net.String(), ifName)
		if route.Gateway != nil {
			cmd += " nexthop=" + route.Gateway.String()
		}
		l.logger.Debug(cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}

func (l *tapListener) deleteRoute(ifName string, route tap_util.Route) error {
	cmd := fmt.Sprintf("netsh interface ip delete route prefix=%s interface=%s store=active",
		route.Net.String(), ifName)
	l.logger.Debug(cmd)
	args := strings.Split(cmd, " ")
	return exec.Command(args[0], args[1:]...).Run()
}

func ipMask(mask net.IPMask) string {
	return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
}
