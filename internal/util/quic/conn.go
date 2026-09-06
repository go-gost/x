package quic

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"net"
)

type cipherConn struct {
	net.PacketConn
	key []byte
}

func CipherPacketConn(conn net.PacketConn, key []byte) net.PacketConn {
	return &cipherConn{
		PacketConn: conn,
		key:        key,
	}
}

func (conn *cipherConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	for {
		n, addr, err = conn.PacketConn.ReadFrom(data)
		if err != nil {
			return n, addr, err
		}
		b, err := conn.decrypt(data[:n])
		if err != nil {
			if _, ok := errors.AsType[aes.KeySizeError](err); ok {
				// Local misconfiguration: surface it instead of looping forever.
				return 0, addr, err
			}
			// Invalid peer datagram: discard and keep listening. Returning the
			// error here would make quic-go close the shared transport.
			continue
		}
		return copy(data, b), addr, nil
	}
}

func (conn *cipherConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	b, err := conn.encrypt(data)
	if err != nil {
		return 0, err
	}

	n, err = conn.PacketConn.WriteTo(b, addr)
	if err != nil {
		return n, err
	}
	if n != len(b) {
		return n, io.ErrShortWrite
	}

	// Report the caller-supplied length, not the encrypted (nonce+tag) length.
	return len(data), nil
}

func (conn *cipherConn) encrypt(data []byte) ([]byte, error) {
	c, err := aes.NewCipher(conn.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, data, nil), nil
}

func (conn *cipherConn) decrypt(data []byte) ([]byte, error) {
	c, err := aes.NewCipher(conn.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
