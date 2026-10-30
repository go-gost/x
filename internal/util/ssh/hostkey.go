package ssh

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ErrNoHostKey is returned when no trusted host key was configured and no
// default known_hosts file is available. Dialers fail closed on this error
// instead of connecting to an unauthenticated server.
var ErrNoHostKey = errors.New("ssh: no trusted host key configured: " +
	"set hostKeyFile or hostKey, or set insecureSkipHostKeyVerify=true to disable verification")

// NewHostKeyCallback builds the HostKeyCallback used by the ssh and sshd
// dialers.
//
//	insecure              accept any host key. This was the previous behavior
//	                      and is now an explicit opt-in.
//	hostKey != ""         pin a single key, given either as an authorized_keys
//	                      line ("ssh-ed25519 AAAA...") or as a SHA256:/MD5:
//	                      fingerprint.
//	knownHostsFile != ""  verify against that known_hosts file.
//
// When none of them is set, ~/.ssh/known_hosts is used if it exists. If there
// is no usable known_hosts file the function returns ErrNoHostKey so that the
// dialer refuses to connect.
func NewHostKeyCallback(knownHostsFile, hostKey string, insecure bool) (ssh.HostKeyCallback, error) {
	if insecure {
		return ssh.InsecureIgnoreHostKey(), nil
	}

	if hostKey = strings.TrimSpace(hostKey); hostKey != "" {
		return fixedHostKeyCallback(hostKey)
	}

	knownHostsFile = strings.TrimSpace(knownHostsFile)
	if knownHostsFile == "" {
		def, err := homedir.Expand("~/.ssh/known_hosts")
		if err != nil {
			return nil, ErrNoHostKey
		}
		if _, err := os.Stat(def); err != nil {
			return nil, ErrNoHostKey
		}
		knownHostsFile = def
	} else {
		expanded, err := homedir.Expand(knownHostsFile)
		if err != nil {
			return nil, fmt.Errorf("ssh: expand hostKeyFile: %w", err)
		}
		knownHostsFile = expanded
	}

	cb, err := knownhosts.New(knownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("ssh: load known_hosts file %q: %w", knownHostsFile, err)
	}
	return cb, nil
}

func fixedHostKeyCallback(hostKey string) (ssh.HostKeyCallback, error) {
	switch {
	case strings.HasPrefix(hostKey, "SHA256:"):
		return fingerprintCallback(hostKey, ssh.FingerprintSHA256), nil
	case strings.HasPrefix(hostKey, "MD5:"):
		return fingerprintCallback(strings.TrimPrefix(hostKey, "MD5:"), ssh.FingerprintLegacyMD5), nil
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKey))
	if err != nil {
		return nil, fmt.Errorf("ssh: parse hostKey: %w", err)
	}
	return ssh.FixedHostKey(pub), nil
}

func fingerprintCallback(want string, fingerprint func(ssh.PublicKey) string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if got := fingerprint(key); got != want {
			return fmt.Errorf("ssh: host key mismatch for %s: presented %s, pinned %s",
				hostname, got, want)
		}
		return nil
	}
}
