package tun

import (
	"errors"
	"os"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

type fakeTunDevice struct {
	wrote [][]byte
}

func (f *fakeTunDevice) File() *os.File { return nil }

func (f *fakeTunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, nil
}

func (f *fakeTunDevice) Write(bufs [][]byte, offset int) (int, error) {
	f.wrote = append(f.wrote, bufs[0][offset:])
	return 1, nil
}

func (f *fakeTunDevice) MTU() (int, error)        { return 1500, nil }
func (f *fakeTunDevice) Name() (string, error)    { return "fake0", nil }
func (f *fakeTunDevice) Events() <-chan tun.Event { return nil }
func (f *fakeTunDevice) Close() error             { return nil }
func (f *fakeTunDevice) BatchSize() int           { return 1 }

// A packet that does not fit the device write buffer must be rejected with an
// error, never panic the process. Field case: a 20546-byte spoke packet hit
// wbuf[:writeOffset+len(p)] with cap 16400 and took down the whole hub.
func TestTunDeviceWriteOversizedPacket(t *testing.T) {
	fake := &fakeTunDevice{}
	dev, _, err := newTunDevice(fake, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	big := make([]byte, maxBufSize+1)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Write panicked on %d-byte packet: %v", len(big), r)
			}
		}()
		n, err := dev.Write(big)
		if !errors.Is(err, ErrPacketTooLarge) {
			t.Fatalf("Write err = %v, want %v", err, ErrPacketTooLarge)
		}
		if n != 0 {
			t.Fatalf("Write n = %d, want 0", n)
		}
	}()
	if len(fake.wrote) != 0 {
		t.Fatalf("oversized packet reached the device, want it dropped")
	}
}

// A device created with a large MTU must accept packets that the default
// 16KB buffer would reject. Field case: tun.mtu raised for jumbo UDP.
func TestTunDeviceWriteLargeMTUAcceptsJumbo(t *testing.T) {
	fake := &fakeTunDevice{}
	dev, _, err := newTunDevice(fake, 32768)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	pkt := make([]byte, 20546)
	n, err := dev.Write(pkt)
	if err != nil {
		t.Fatalf("Write err = %v, want nil", err)
	}
	if n != len(pkt) {
		t.Fatalf("Write n = %d, want %d", n, len(pkt))
	}
	if len(fake.wrote) != 1 {
		t.Fatalf("device writes = %d, want 1", len(fake.wrote))
	}
}

// A normal-size packet must still pass through untouched.
func TestTunDeviceWriteNormalPacket(t *testing.T) {
	fake := &fakeTunDevice{}
	dev, _, err := newTunDevice(fake, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer dev.Close()

	pkt := make([]byte, 1500)
	n, err := dev.Write(pkt)
	if err != nil {
		t.Fatalf("Write err = %v, want nil", err)
	}
	if n != len(pkt) {
		t.Fatalf("Write n = %d, want %d", n, len(pkt))
	}
	if len(fake.wrote) != 1 {
		t.Fatalf("device writes = %d, want 1", len(fake.wrote))
	}
}
