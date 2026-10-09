package tun

// prefixRoute is a LAN route the hub holds: the member that reaches the
// prefix, and the members allowed to use it (empty = everyone).
type prefixRoute struct {
	Peer  string
	Allow []string
}
