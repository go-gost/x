package http

import (
	"bytes"
	"context"
	"io"
	"math"
	"time"

	"github.com/go-gost/core/logger"
	"github.com/go-gost/x/internal/util/sniffing"
	ws_util "github.com/go-gost/x/internal/util/ws"
	xrecorder "github.com/go-gost/x/recorder"
	"golang.org/x/time/rate"
)

// sniffingWebsocketFrame relays WebSocket frames between the client (rw)
// and the backend (cc) while sampling frames for recording. Two goroutines
// run in parallel — one per direction — copying frames and recording them
// at the configured sample rate.
//
// The first direction to encounter an error terminates the relay.
func (h *httpHandler) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriter, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 1)

	sampleRate := h.md.sniffingWebsocketSampleRate
	if sampleRate == 0 {
		sampleRate = sniffing.DefaultSampleRate
	}
	if sampleRate < 0 {
		sampleRate = math.MaxFloat64
	}

	go h.copyWebsocketDirection(ctx, cc, rw, "client", ro, sampleRate, log, errc)
	go h.copyWebsocketDirection(ctx, rw, cc, "server", ro, sampleRate, log, errc)

	<-errc
	return nil
}

// copyWebsocketDirection copies WebSocket frames from r to w in a loop
// until an error occurs. Each frame is recorded (subject to the rate
// limiter) with directional metadata — "client" for frames originating
// from the client, "server" for frames from the backend.
//
// The ro parameter is cloned at the start so per-frame mutations are
// isolated from the caller.
func (h *httpHandler) copyWebsocketDirection(ctx context.Context, r io.Reader, w io.Writer, from string, ro *xrecorder.HandlerRecorderObject, sampleRate float64, log logger.Logger, errc chan<- error) {
	if ro == nil {
		ro = &xrecorder.HandlerRecorderObject{}
	}
	ro2 := &xrecorder.HandlerRecorderObject{}
	*ro2 = *ro
	ro2.HTTP = nil
	r2 := ro2

	limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

	buf := &bytes.Buffer{}
	for {
		start := time.Now()

		if err := h.copyWebsocketFrame(w, r, buf, from, r2); err != nil {
			errc <- err
			return
		}

		if limiter.Allow() {
			r2.Duration = time.Since(start)
			r2.Time = time.Now()
			if err := r2.Record(ctx, h.recorder.Recorder); err != nil {
				log.Errorf("record: %v", err)
			}
		}
	}
}

// copyWebsocketFrame reads a single WebSocket frame from r, records its
// metadata and optionally its payload, then writes it to w.
//
// The payload is tee'd: it is copied to buf for recording (up to the
// configured body size limit) and then forwarded by reconstructing the
// frame with a MultiReader that replays the captured bytes followed by
// the remaining data.
//
// Directional byte counts are set on the recorder object — InputBytes
// for client frames, OutputBytes for server frames.
func (h *httpHandler) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
	fr := ws_util.Frame{}
	if _, err = fr.ReadFrom(r); err != nil {
		return err
	}

	ws := &xrecorder.WebsocketRecorderObject{
		From:    from,
		Fin:     fr.Header.Fin,
		Rsv1:    fr.Header.Rsv1,
		Rsv2:    fr.Header.Rsv2,
		Rsv3:    fr.Header.Rsv3,
		OpCode:  int(fr.Header.OpCode),
		Masked:  fr.Header.Masked,
		MaskKey: fr.Header.MaskKey,
		Length:  fr.Header.PayloadLength,
	}
	if bodySize := sniffing.ClampBodySize(h.recorder.Options); bodySize > 0 {
		buf.Reset()
		if _, err := io.Copy(buf, io.LimitReader(fr.Data, int64(bodySize))); err != nil {
			return err
		}
		ws.Payload = buf.Bytes()
	}

	ro.Websocket = ws
	length := uint64(fr.Header.Length()) + uint64(fr.Header.PayloadLength)
	if from == "client" {
		ro.InputBytes = length
		ro.OutputBytes = 0
	} else {
		ro.InputBytes = 0
		ro.OutputBytes = length
	}

	// Reconstruct the frame by prepending any captured payload bytes
	// before the (possibly truncated) original data stream.
	fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
	if _, err := fr.WriteTo(w); err != nil {
		return err
	}

	return nil
}
