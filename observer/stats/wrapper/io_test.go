package wrapper

import (
	"testing"

	"github.com/go-gost/core/observer/stats"
	ostats "github.com/go-gost/x/observer/stats"
)

type fakeReadWriter struct {
	readBuf  []byte
	readPos  int
	writeBuf []byte
}

func (rw *fakeReadWriter) Read(b []byte) (int, error) {
	if rw.readPos >= len(rw.readBuf) {
		return 0, nil
	}
	n := copy(b, rw.readBuf[rw.readPos:])
	rw.readPos += n
	return n, nil
}

func (rw *fakeReadWriter) Write(b []byte) (int, error) {
	rw.writeBuf = append(rw.writeBuf, b...)
	return len(b), nil
}

func TestWrapReadWriter_Nil(t *testing.T) {
	// nil rw
	if result := WrapReadWriter(nil, ostats.NewStats(false)); result != nil {
		t.Error("WrapReadWriter with nil rw should return nil")
	}
	// nil stats
	frw := &fakeReadWriter{}
	if result := WrapReadWriter(frw, nil); result != frw {
		t.Error("WrapReadWriter with nil stats should return original rw")
	}
	// both nil
	if result := WrapReadWriter(nil, nil); result != nil {
		t.Error("WrapReadWriter with both nil should return nil")
	}
}

func TestWrapReadWriter_Read(t *testing.T) {
	st := ostats.NewStats(false)
	frw := &fakeReadWriter{readBuf: []byte("testdata")}
	wrapped := WrapReadWriter(frw, st)

	buf := make([]byte, 8)
	n, _ := wrapped.Read(buf)
	if n != 8 {
		t.Fatalf("read n = %d, want 8", n)
	}
	if st.Get(stats.KindInputBytes) != 8 {
		t.Errorf("inputBytes = %d, want 8", st.Get(stats.KindInputBytes))
	}
}

func TestWrapReadWriter_Write(t *testing.T) {
	st := ostats.NewStats(false)
	frw := &fakeReadWriter{}
	wrapped := WrapReadWriter(frw, st)

	n, _ := wrapped.Write([]byte("hello"))
	if n != 5 {
		t.Fatalf("write n = %d, want 5", n)
	}
	if st.Get(stats.KindOutputBytes) != 5 {
		t.Errorf("outputBytes = %d, want 5", st.Get(stats.KindOutputBytes))
	}
}

func TestWrapReadWriter_ReadWrite(t *testing.T) {
	st := ostats.NewStats(false)
	frw := &fakeReadWriter{readBuf: []byte("abcdefghij")}
	wrapped := WrapReadWriter(frw, st)

	buf := make([]byte, 5)
	wrapped.Read(buf)  // reads 5 bytes
	wrapped.Write([]byte("xyz")) // writes 3 bytes

	if st.Get(stats.KindInputBytes) != 5 {
		t.Errorf("inputBytes = %d, want 5", st.Get(stats.KindInputBytes))
	}
	if st.Get(stats.KindOutputBytes) != 3 {
		t.Errorf("outputBytes = %d, want 3", st.Get(stats.KindOutputBytes))
	}
}
