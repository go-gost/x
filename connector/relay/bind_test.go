package relay

import (
	"net"
	"testing"

	"github.com/go-gost/relay"
)

// A port-only bind address such as ":22" (used by the rtcp listener when a
// service is configured without an explicit host) must be sent to the server
// as "0.0.0.0:22". Joining the whole address instead of the port yields
// "0.0.0.0::22", which the server cannot listen on.
func TestBindPortOnlyAddress(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	type request struct {
		host string
		port uint16
	}
	got := make(chan request, 1)
	errc := make(chan error, 1)

	go func() {
		req := relay.Request{}
		if _, err := req.ReadFrom(server); err != nil {
			errc <- err
			return
		}

		var r request
		for _, f := range req.Features {
			if fa, ok := f.(*relay.AddrFeature); ok {
				r = request{host: fa.Host, port: fa.Port}
			}
		}
		got <- r

		af := &relay.AddrFeature{}
		af.ParseFrom("0.0.0.0:22")
		resp := relay.Response{
			Version:  relay.Version1,
			Status:   relay.StatusOK,
			Features: []relay.Feature{af},
		}
		if _, err := resp.WriteTo(server); err != nil {
			errc <- err
		}
	}()

	c := &relayConnector{}
	if _, err := c.bind(client, relay.CmdBind, "tcp", ":22"); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-errc:
		t.Fatal(err)
	case r := <-got:
		if r.host != "0.0.0.0" || r.port != 22 {
			t.Fatalf("bind address = %q:%d, want %q:%d", r.host, r.port, "0.0.0.0", 22)
		}
	}
}
