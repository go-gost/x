package tunnel

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

func (ep *entrypoint) sniffingWebsocketFrame(ctx context.Context, rw, cc io.ReadWriteCloser, ro *xrecorder.HandlerRecorderObject, log logger.Logger) error {
	errc := make(chan error, 2)

	sampleRate := ep.websocketSampleRate
	if sampleRate == 0 {
		sampleRate = sniffing.DefaultSampleRate
	}
	if sampleRate < 0 {
		sampleRate = math.MaxFloat64
	}

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := ep.copyWebsocketFrame(cc, rw, buf, "client", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	go func() {
		ro2 := &xrecorder.HandlerRecorderObject{}
		*ro2 = *ro
		ro := ro2

		limiter := rate.NewLimiter(rate.Limit(sampleRate), int(sampleRate))

		buf := &bytes.Buffer{}
		for {
			start := time.Now()

			if err := ep.copyWebsocketFrame(rw, cc, buf, "server", ro); err != nil {
				errc <- err
				return
			}

			if limiter.Allow() {
				ro.Duration = time.Since(start)
				ro.Time = time.Now()
				if err := ro.Record(ctx, ep.recorder.Recorder); err != nil {
					log.Errorf("record: %v", err)
				}
			}
		}
	}()

	<-errc
	rw.Close()
	cc.Close()
	<-errc
	return nil
}

func (ep *entrypoint) copyWebsocketFrame(w io.Writer, r io.Reader, buf *bytes.Buffer, from string, ro *xrecorder.HandlerRecorderObject) (err error) {
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
	if opts := ep.recorder.Options; opts != nil && opts.HTTPBody {
		bodySize := opts.MaxBodySize
		if bodySize <= 0 {
			bodySize = sniffing.DefaultBodySize
		}
		if bodySize > sniffing.MaxBodySize {
			bodySize = sniffing.MaxBodySize
		}

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

	fr.Data = io.MultiReader(bytes.NewReader(buf.Bytes()), fr.Data)
	if _, err := fr.WriteTo(w); err != nil {
		return err
	}

	return nil
}