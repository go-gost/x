package tun

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	tun_util "github.com/go-gost/x/internal/util/tun"
	"github.com/songgao/water"
)

func (l *tunListener) createTun() (ifce *water.Interface, ip net.IP, err error) {
	ifce, err = water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: l.md.config.Name,
		},
	})
	if err != nil {
		return
	}

	if err = l.exeCmd(fmt.Sprintf("ip link set dev %s mtu %d", ifce.Name(), l.md.config.MTU)); err != nil {
		l.logger.Warn(err)
	}

	if err = l.exeCmd(fmt.Sprintf("ip address add %s dev %s", l.md.config.Net, ifce.Name())); err != nil {
		l.logger.Warn(err)
	}

	if err = l.exeCmd(fmt.Sprintf("ip link set dev %s up", ifce.Name())); err != nil {
		l.logger.Warn(err)
	}

	if err = l.addRoutes(ifce.Name(), l.md.config.Routes...); err != nil {
		return
	}

	return
}

func (l *tunListener) exeCmd(cmd string) error {
	l.logger.Debug(cmd)

	args := strings.Split(cmd, " ")
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		return fmt.Errorf("%s: %v", cmd, err)
	}

	return nil
}

func (l *tunListener) addRoutes(ifName string, routes ...tun_util.Route) error {
	for _, route := range routes {
		cmd := fmt.Sprintf("ip route add %s dev %s", route.Net.String(), ifName)
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			l.logger.Warnf("%s: %v", cmd, er)
		}
	}
	return nil
}
