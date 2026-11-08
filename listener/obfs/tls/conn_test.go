package tls

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"testing"

	dissector "github.com/go-gost/tls-dissector"
)

// The first Write carries the server hello, so it goes through a separate
// path. Data longer than one record must still be written in full.
func TestObfsTLSConnFirstWriteLargerThanRecord(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	conn := &obfsTLSConn{Conn: server}

	go func() {
		hello := &dissector.ClientHelloMsg{
			Version:            tls.VersionTLS12,
			SessionID:          make([]byte, 32),
			CipherSuites:       []uint16{0xcca8},
			CompressionMethods: []uint8{0x00},
			Extensions: []dissector.Extension{
				&dissector.SessionTicketExtension{Data: []byte("ping")},
			},
		}
		b, _ := hello.Encode()
		record := &dissector.Record{Type: dissector.Handshake, Version: tls.VersionTLS10, Opaque: b}
		record.WriteTo(client)
	}()

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}

	data := bytes.Repeat([]byte("x"), maxTLSDataLen+100)
	go func() {
		defer server.Close()
		if n, err := conn.Write(data); err != nil || n != len(data) {
			t.Errorf("write: %d, %v", n, err)
		}
	}()

	var got []byte
	for i := 0; ; i++ {
		record := &dissector.Record{}
		if _, err := record.ReadFrom(client); err != nil {
			break
		}
		// skip the server hello and the change cipher spec records.
		if i >= 2 {
			got = append(got, record.Opaque...)
		}
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("got %d bytes, want %d", len(got), len(data))
	}
}
