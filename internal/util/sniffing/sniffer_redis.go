package sniffing

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	xnet "github.com/go-gost/x/internal/net"
	xrecorder "github.com/go-gost/x/recorder"
)

// ParseRedisMetadata reads a single RESP message from r and populates
// ro.Redis with the extracted command and key.
//
// r must provide exactly one RESP message — the caller is expected to
// wrap the conn with io.TeeReader(conn, buf) so that the bytes are both
// parsed and captured in buf for replay to the upstream.
//
// On success, ro.Redis is non-nil. On error (malformed RESP, truncated
// message), ro.Redis is nil and the caller should fall back to raw
// forwarding.
func ParseRedisMetadata(r io.Reader, ro *xrecorder.HandlerRecorderObject) error {
	br := bufio.NewReader(r)

	b, err := br.ReadByte()
	if err != nil {
		return err
	}

	switch b {
	case '*':
		return parseRESPArray(br, ro)
	case '$':
		s, err := readBulkStringPayload(br)
		if err != nil {
			return err
		}
		ro.Redis = &xrecorder.RedisRecorderObject{Command: strings.ToUpper(s)}
		return nil
	case '+', '-':
		s, err := readRESPLine(br)
		if err != nil {
			return err
		}
		ro.Redis = &xrecorder.RedisRecorderObject{Command: strings.ToUpper(s)}
		return nil
	case ':':
		s, err := readRESPLine(br)
		if err != nil {
			return err
		}
		ro.Redis = &xrecorder.RedisRecorderObject{Command: s}
		return nil
	default:
		return fmt.Errorf("unknown RESP type byte: 0x%02x", b)
	}
}

// readRESPLine reads until '\n' and strips the trailing "\r\n".
func readRESPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readBulkStringPayload reads <len>\r\n<bytes>\r\n (the leading '$' must
// already be consumed by the caller). Returns the string value.
func readBulkStringPayload(br *bufio.Reader) (string, error) {
	line, err := readRESPLine(br)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return "", fmt.Errorf("invalid bulk string length: %s", line)
	}
	if n < 0 {
		return "", nil // null bulk string
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return "", err
	}
	// consume trailing \r\n
	if _, err := br.Discard(2); err != nil {
		return "", err
	}
	return string(buf), nil
}

// parseRESPArray parses a RESP array: <n>\r\n, then n bulk strings.
// The leading '*' must already be consumed by the caller.
func parseRESPArray(br *bufio.Reader, ro *xrecorder.HandlerRecorderObject) error {
	line, err := readRESPLine(br)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return fmt.Errorf("invalid RESP array length: %s", line)
	}
	if n < 0 {
		return nil // null array
	}

	for i := 0; i < n; i++ {
		b, err := br.ReadByte()
		if err != nil {
			return err
		}
		if b != '$' {
			return fmt.Errorf("expected bulk string in RESP array, got byte 0x%02x", b)
		}
		s, err := readBulkStringPayload(br)
		if err != nil {
			return err
		}
		if i == 0 {
			// ponytail: first element allocated inline, second appended.
			// A nil check on the first element is enough — RESP
			// commands always have at least one element.
			ro.Redis = &xrecorder.RedisRecorderObject{Command: strings.ToUpper(s)}
		} else if i == 1 {
			ro.Redis.Key = s
		}
	}
	if ro.Redis == nil {
		ro.Redis = &xrecorder.RedisRecorderObject{}
	}
	return nil
}

// HandleRedis proxies a sniffed Redis connection. It parses the first RESP
// message for metadata recording, then replays the captured bytes to the
// upstream and pipes traffic bidirectionally.
//
// The network parameter is passed through to the injected dial function.
// Bypass checks are not performed here — Redis has no host concept for
// bypass to match against; protocol-based routing is handled by the
// hop selector in the forwarder path.
func (h *Sniffer) HandleRedis(ctx context.Context, network string, conn net.Conn, opts ...HandleOption) error {
	var ho HandleOptions
	for _, opt := range opts {
		opt(&ho)
	}

	buf := new(bytes.Buffer)
	if err := ParseRedisMetadata(io.TeeReader(conn, buf), ho.recorderObject); err != nil {
		return err
	}

	log := ho.log
	ro := ho.recorderObject

	dial := ho.dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	cc, err := dial(ctx, network, ro.Host)
	if err != nil {
		return err
	}
	defer cc.Close()

	log = log.WithFields(map[string]any{"src": cc.LocalAddr().String(), "dst": cc.RemoteAddr().String()})
	ro.SrcAddr = cc.LocalAddr().String()
	ro.DstAddr = cc.RemoteAddr().String()

	if _, err := buf.WriteTo(cc); err != nil {
		return err
	}

	log.Infof("%s <-> %s", ro.RemoteAddr, ro.Host)
	xnet.Pipe(ctx, conn, cc)
	log.WithFields(map[string]any{
		"duration": time.Since(ro.Time),
	}).Infof("%s >-< %s", ro.RemoteAddr, ro.Host)

	return nil
}
