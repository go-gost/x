package tun

import (
	"net"

	"github.com/go-gost/core/router"
)

type Config struct {
	Name string
	Net  []net.IPNet
	// peer addr of point-to-point on MacOS
	Peer    string
	MTU     int
	Gateway net.IP
	Router  router.Router
	DNS []net.IP
}
