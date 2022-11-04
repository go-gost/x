//go:build !linux && !windows && !darwin

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
	ip, _, _ = net.ParseCIDR(l.md.config.Net)

	ifce, err := water.New(water.Config{
		DeviceType: water.TAP,
	})
	if err != nil {
		return
	}

	dev = ifce
	name = ifce.Name()

	var cmd string
	if l.md.config.Net != "" {
		cmd = fmt.Sprintf("ifconfig %s inet %s mtu %d up", ifce.Name(), l.md.config.Net, l.md.config.MTU)
	} else {
		cmd = fmt.Sprintf("ifconfig %s mtu %d up", ifce.Name(), l.md.config.MTU)
	}
	l.logger.Debug(cmd)

	args := strings.Split(cmd, " ")
	if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
		err = fmt.Errorf("%s: %v", cmd, er)
		return
	}

	if err = l.addRoutes(ifce.Name(), l.md.config.Routes...); err != nil {
		return
	}

	return
}

func (l *tapListener) addRoutes(ifName string, routes ...tap_util.Route) error {
	for _, route := range routes {
		cmd := fmt.Sprintf("route add -net %s dev %s", route.Net.String(), ifName)
		if route.Gateway != nil {
			cmd += " gw " + route.Gateway.String()
		}
		l.logger.Debug(cmd)
		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			return fmt.Errorf("%s: %v", cmd, er)
		}
	}
	return nil
}
