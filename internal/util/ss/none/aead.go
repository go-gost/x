// Package none provides a no-op cipher for Shadowsocks that passes data
// through without encryption. It implements the go-shadowsocks2 core.ShadowCipher
// interface. This cipher is intended for debugging, testing, and compatibility
// purposes and MUST NOT be used in production.
package none

// noopAEAD is a cipher.AEAD that performs no encryption or authentication.
// All data passes through unchanged.
type noopAEAD struct{}

// NonceSize returns 0 since no nonce is needed.
func (noopAEAD) NonceSize() int { return 0 }

// Overhead returns 0 since no authentication tag is added.
func (noopAEAD) Overhead() int { return 0 }

// Seal appends plaintext to dst without encryption.
func (noopAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return append(dst, plaintext...)
}

// Open appends ciphertext to dst without decryption.
func (noopAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return append(dst, ciphertext...), nil
}
