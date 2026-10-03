package tun

import (
	"context"
	"net"
)

// PeerAuthorizer decides whether the peer that sent a registration may claim the
// addresses in it.
//
// It exists because an auth.Authenticator cannot answer the question: onKeepalive
// passes the claimed address as the user name and the frame's key as the
// password, so an auther never learns which peer is claiming and cannot bind a
// claim to one. The peer key is already authenticated by the transport — a p2p
// hub's allowlist is what routed the stream here — so this is authorization, not
// authentication: it decides which addresses a known peer may hold.
//
// peer is the transport's name for the sender, verbatim: a "host:port" for a
// socket peer, a p2p peer key for a p2p one. ips is every address the frame
// claimed, and an implementation should require the whole set rather than a
// subset: peerTable.set is last-writer-wins per address, so a peer that also
// claims a neighbour's address takes that route over.
type PeerAuthorizer interface {
	Authorize(ctx context.Context, peer string, ips []net.IP) bool
}
