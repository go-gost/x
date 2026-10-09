package tun

// PrefixRoute is a LAN route the hub holds: the member that reaches the
// prefix, and the members allowed to use it (empty = everyone).
//
// It is exported because the hub that installs these routes lives in another
// module: the tun p2p handler is handed to it as a handler.Handler, so it
// names the map it passes by this type. Nothing else in x or outside it
// constructs one.
type PrefixRoute struct {
	Peer  string
	Allow []string
}
