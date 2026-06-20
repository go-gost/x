package utls

import (
	utls "github.com/refraction-networking/utls"
)

// fingerprintMap maps user-facing string names to uTLS ClientHelloID presets.
// Each _Auto alias automatically tracks the latest known fingerprint for that
// browser in the uTLS library.
var fingerprintMap = map[string]utls.ClientHelloID{
	"chrome":            utls.HelloChrome_Auto,
	"firefox":           utls.HelloFirefox_Auto,
	"ios":               utls.HelloIOS_Auto,
	"safari":            utls.HelloSafari_Auto,
	"edge":              utls.HelloEdge_Auto,
	"randomized":        utls.HelloRandomized,
	"randomized-alpn":   utls.HelloRandomizedALPN,
	"randomized-noalpn": utls.HelloRandomizedNoALPN,
	"golang":            utls.HelloGolang,
	"custom":            utls.HelloCustom,
}

// GetClientHelloID returns the utls.ClientHelloID for the given fingerprint
// name. The empty string and "golang" both return ok=false, signalling the
// caller to fall through to standard crypto/tls. Unknown names also return
// ok=false.
func GetClientHelloID(name string) (utls.ClientHelloID, bool) {
	if name == "" || name == "golang" {
		return utls.ClientHelloID{}, false
	}
	id, ok := fingerprintMap[name]
	return id, ok
}
