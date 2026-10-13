package tun

import "github.com/songgao/water/waterutil"

// IPv4Packet and IPv6Packet are the only ways a reader should ask waterutil
// which family a buffer is.
//
// waterutil.IsIPv4/IsIPv6 index packet[0] with no length check, so an empty
// buffer panics there instead of reporting "neither". An empty buffer is not
// hypothetical: a device may legally return zero bytes with no error — an
// Android VpnService tun fd does exactly that — and that read produced the
// "panic: runtime error: index out of range [0] with length 0" that took the
// spoke down on 2026-10-12, three times, with no stack left in crash.log. In a
// c-shared library the runtime cannot unwind past the cgo boundary, so the
// panic took the app with it.
//
// Every packet classifier needs this guard: the read loops in handler/tun,
// the association classifier in handler/router, and anything added later.
func IPv4Packet(b []byte) bool { return len(b) > 0 && waterutil.IsIPv4(b) }

func IPv6Packet(b []byte) bool { return len(b) > 0 && waterutil.IsIPv6(b) }
