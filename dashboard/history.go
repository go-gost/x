package dashboard

// eventRing is a fixed-size ring of diagnostic events.
type eventRing struct {
	buf  []EventRecord
	next int
	full bool
}

func newEventRing(size int) eventRing {
	return eventRing{buf: make([]EventRecord, size)}
}

func (r *eventRing) add(e EventRecord) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.next] = e
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// list returns the events oldest first. It never returns nil so the JSON
// snapshot always carries an array.
func (r *eventRing) list() []EventRecord {
	if len(r.buf) == 0 {
		return []EventRecord{}
	}
	if !r.full {
		return append([]EventRecord{}, r.buf[:r.next]...)
	}
	out := make([]EventRecord, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}

// historyRing is a fixed-size ring of periodic samples.
type historyRing struct {
	buf  []HistoryPoint
	next int
	full bool
}

func newHistoryRing(size int) historyRing {
	return historyRing{buf: make([]HistoryPoint, size)}
}

func (r *historyRing) add(p HistoryPoint) {
	if len(r.buf) == 0 {
		return
	}
	r.buf[r.next] = p
	r.next = (r.next + 1) % len(r.buf)
	if r.next == 0 {
		r.full = true
	}
}

// list returns the samples oldest first.
func (r *historyRing) list() []HistoryPoint {
	if len(r.buf) == 0 {
		return nil
	}
	if !r.full {
		return append([]HistoryPoint(nil), r.buf[:r.next]...)
	}
	out := make([]HistoryPoint, 0, len(r.buf))
	out = append(out, r.buf[r.next:]...)
	out = append(out, r.buf[:r.next]...)
	return out
}
