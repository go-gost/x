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

	// On Windows, InterfaceName is a selection filter, not a name assignment.
	// Passing it to water.New() causes the library to look for an existing
	// adapter with that friendly name in the registry, which fails if no
	// adapter with that name exists yet. Instead, let Windows auto-name the
	// new adapter, then rename it afterwards if the user requested a name.
	ifce, err := water.New(water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			ComponentID: l.md.config.ComponentID,
			Network:     l.md.config.Net,
		},
	})
	if err != nil {
		return
	}

	dev = ifce
	name = ifce.Name()

	// Rename the adapter if the user specified a custom name.
	if l.md.config.Name != "" && l.md.config.Name != name {
		renameCmd := fmt.Sprintf("netsh interface set interface name=%s newname=%s",
			name, l.md.config.Name)
		l.logger.Debug(renameCmd)
		args := strings.Split(renameCmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er == nil {
			name = l.md.config.Name
		} else {
			l.logger.Warnf("failed to rename adapter from %s to %s: %v",
				name, l.md.config.Name, er)
		}
	}

	if ip != nil && ipNet != nil {
		cmd := fmt.Sprintf("netsh interface ip set address name=%s "+
			"source=static addr=%s mask=%s gateway=none",
			name, ip.String(), ipMask(ipNet.Mask))
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			err = fmt.Errorf("%s: %v", cmd, er)
			return
		}
	}

	if err = l.addRoutes(name, l.md.config.Routes...); err != nil {
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
