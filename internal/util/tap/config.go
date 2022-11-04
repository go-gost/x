package tap

import "net"

// Route is an IP routing entry
type Route struct {
	Net     net.IPNet
	Gateway net.IP
}
type Config struct {
	Name    string
	Net     string
	MTU     int
	Gateway string
	Routes  []Route
}
