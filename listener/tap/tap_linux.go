package tap

import (
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/songgao/water"
)

func (l *tapListener) createTap() (ifce *water.Interface, ip net.IP, err error) {
	ifce, err = water.New(water.Config{
		DeviceType: water.TAP,
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

	if l.md.config.Net != "" {
		if err = l.exeCmd(fmt.Sprintf("ip address add %s dev %s", l.md.config.Net, ifce.Name())); err != nil {
			l.logger.Warn(err)
		}
	}

	if err = l.exeCmd(fmt.Sprintf("ip link set dev %s up", ifce.Name())); err != nil {
		l.logger.Warn(err)
	}

	if err = l.addRoutes(ifce.Name(), l.md.config.Gateway, l.md.config.Routes...); err != nil {
		return
	}

	return
}

func (l *tapListener) exeCmd(cmd string) error {
	l.logger.Debug(cmd)

	args := strings.Split(cmd, " ")
	if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
		return fmt.Errorf("%s: %v", cmd, err)
	}

	return nil
}

func (l *tapListener) addRoutes(ifName string, gw string, routes ...string) error {
	for _, route := range routes {
		cmd := fmt.Sprintf("ip route add %s via %s dev %s", route, gw, ifName)
		l.logger.Debug(cmd)

		args := strings.Split(cmd, " ")
		if er := exec.Command(args[0], args[1:]...).Run(); er != nil {
			l.logger.Warnf("%s: %v", cmd, er)
		}
	}
	return nil
}
