package socks

const (
	// MethodTLS is an extended SOCKS5 method with tls encryption support.
	MethodTLS uint8 = 0x80
	// MethodTLSAuth is an extended SOCKS5 method with tls encryption and authentication support.
	MethodTLSAuth uint8 = 0x82
	// MethodMux is an extended SOCKS5 method for stream multiplexing.
	MethodMux = 0x88
)

const (
	// CmdResolve is a Tor SOCKS5 extension command (0xF0) for resolving
	// a hostname to an IP address via Tor's DNS.
	CmdResolve uint8 = 0xF0
	// CmdResolvePTR is a Tor SOCKS5 extension command (0xF1) for reverse
	// DNS lookup (IP to hostname) via Tor's DNS.
	CmdResolvePTR uint8 = 0xF1

	// CmdMuxBind is an extended SOCKS5 request CMD for
	// multiplexing transport with the binding server.
	CmdMuxBind uint8 = 0xF2
	// CmdUDPTun is an extended SOCKS5 request CMD for UDP over TCP.
	CmdUDPTun uint8 = 0xF3
)
