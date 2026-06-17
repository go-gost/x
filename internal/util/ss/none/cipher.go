package none

import (
	"crypto/cipher"
	"net"
	"time"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/shadowaead"
)

// Cipher is a no-op Shadowsocks cipher that passes data through without
// encryption. It supports both TCP and UDP via the standard go-shadowsocks2
// ShadowCipher interface. The SS protocol framing (length-prefixed chunks)
// is preserved, but no encryption or authentication is applied.
var Cipher core.ShadowCipher = &noneCipher{}

type noneCipher struct{}

// SaltSize returns a non-zero value so the go-shadowsocks2 bloom ring
// does not reject every connection as a repeated salt. The 16-byte salt
// is generated randomly and is not used for any actual key derivation.
func (noneCipher) SaltSize() int { return 16 }

// KeySize returns 0 since no encryption key is used.
func (noneCipher) KeySize() int { return 0 }

// NonceSize returns 0 since no nonce is used.
func (noneCipher) NonceSize() int { return 0 }

// TagSize returns 0 since no authentication tag is used.
func (noneCipher) TagSize() int { return 0 }

// Key returns nil.
func (noneCipher) Key() []byte { return nil }

// Keys returns nil.
func (noneCipher) Keys() [][]byte { return nil }

// FirstKey returns nil.
func (noneCipher) FirstKey() []byte { return nil }

// Encrypter returns a no-op AEAD.
func (noneCipher) Encrypter(key, salt []byte) (cipher.AEAD, error) {
	return noopAEAD{}, nil
}

// Decrypter returns a no-op AEAD.
func (noneCipher) Decrypter(key, salt []byte) (cipher.AEAD, error) {
	return noopAEAD{}, nil
}

// TCPConn wraps a net.Conn with the no-op cipher using the standard
// go-shadowsocks2 AEAD stream connection. The SS protocol framing
// (salt + length-prefixed chunks) is preserved but unencrypted.
func (c noneCipher) TCPConn(conn net.Conn, users []core.UserConfig, role int) core.TCPConn {
	return shadowaead.NewConn(conn, c)
}

// NewUDPSessionManager creates a UDP session manager using the standard
// go-shadowsocks2 AEAD UDP implementation. Packets are framed but
// unencrypted.
func (c noneCipher) NewUDPSessionManager(timeout time.Duration, users []core.UserConfig, windowSize, role int) core.UDPSessionManager {
	return shadowaead.NewAEADSessionManager(c, timeout, role)
}
