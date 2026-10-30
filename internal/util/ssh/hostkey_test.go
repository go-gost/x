package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/mitchellh/go-homedir"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testSigner(t *testing.T) ssh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signer, err := ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	return signer
}

func TestNewHostKeyCallbackInsecure(t *testing.T) {
	signer := testSigner(t)

	cb, err := NewHostKeyCallback("", "", true)
	require.NoError(t, err)
	require.NoError(t, cb("anywhere", nil, signer.PublicKey()))
}

func TestNewHostKeyCallbackFingerprint(t *testing.T) {
	trusted := testSigner(t)
	other := testSigner(t)

	cb, err := NewHostKeyCallback("", ssh.FingerprintSHA256(trusted.PublicKey()), false)
	require.NoError(t, err)
	require.NoError(t, cb("host:22", nil, trusted.PublicKey()))
	require.Error(t, cb("host:22", nil, other.PublicKey()))
}

func TestNewHostKeyCallbackMD5Fingerprint(t *testing.T) {
	trusted := testSigner(t)

	cb, err := NewHostKeyCallback("", "MD5:"+ssh.FingerprintLegacyMD5(trusted.PublicKey()), false)
	require.NoError(t, err)
	require.NoError(t, cb("host:22", nil, trusted.PublicKey()))
}

func TestNewHostKeyCallbackAuthorizedKey(t *testing.T) {
	trusted := testSigner(t)
	other := testSigner(t)

	cb, err := NewHostKeyCallback("", string(ssh.MarshalAuthorizedKey(trusted.PublicKey())), false)
	require.NoError(t, err)
	require.NoError(t, cb("host:22", nil, trusted.PublicKey()))
	require.Error(t, cb("host:22", nil, other.PublicKey()))
}

func TestNewHostKeyCallbackInvalidHostKey(t *testing.T) {
	_, err := NewHostKeyCallback("", "not-a-key", false)
	require.Error(t, err)
}

func TestNewHostKeyCallbackKnownHosts(t *testing.T) {
	trusted := testSigner(t)
	other := testSigner(t)

	addr := "[127.0.0.1]:2222"
	path := filepath.Join(t.TempDir(), "known_hosts")
	require.NoError(t, os.WriteFile(path,
		[]byte(knownhosts.Line([]string{addr}, trusted.PublicKey())+"\n"), 0600))

	cb, err := NewHostKeyCallback(path, "", false)
	require.NoError(t, err)

	remote := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 2222}
	require.NoError(t, cb(addr, remote, trusted.PublicKey()))
	require.Error(t, cb(addr, remote, other.PublicKey()))
}

func TestNewHostKeyCallbackMissingKnownHosts(t *testing.T) {
	_, err := NewHostKeyCallback(filepath.Join(t.TempDir(), "missing"), "", false)
	require.Error(t, err)
}

func TestNewHostKeyCallbackDefaultsToUserKnownHosts(t *testing.T) {
	// Isolate the home directory so the result does not depend on the host.
	oldDisableCache := homedir.DisableCache
	homedir.DisableCache = true
	t.Cleanup(func() { homedir.DisableCache = oldDisableCache })
	t.Setenv("HOME", t.TempDir())

	_, err := NewHostKeyCallback("", "", false)
	require.ErrorIs(t, err, ErrNoHostKey)
}
