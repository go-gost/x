package ss

import (
	"strings"

	"github.com/go-gost/go-shadowsocks2/core"
	"github.com/go-gost/go-shadowsocks2/utils"

	"github.com/go-gost/x/internal/util/ss/none"
)

// ShadowCipher derives a cipher from method + password.
// method is case-insensitive; "dummy"/"none" select the pass-through cipher.
// An empty method or password returns (nil, nil), meaning no encryption.
func ShadowCipher(method, password string) (core.ShadowCipher, error) {
	if method == "" || password == "" {
		return nil, nil
	}
	if strings.EqualFold(method, "dummy") || strings.EqualFold(method, "none") {
		return none.Cipher, nil
	}
	return utils.PickCipher(method, password) // lowercases internally
}
