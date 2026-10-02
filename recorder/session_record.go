package recorder

import "time"

const (
	PhaseInterim = "interim"
	PhaseFinal   = "final"
)

type SessionRecord struct {
	HandlerRecorderObject
	SessionID        string        `json:"sessionID"`
	RecordIndex      uint64        `json:"recordIndex"`
	Phase            string        `json:"phase"`
	InputBytesDelta  uint64        `json:"inputBytesDelta"`
	OutputBytesDelta uint64        `json:"outputBytesDelta"`
	DurationDelta    time.Duration `json:"durationDelta"`
}

type cursor struct {
	startedAt   time.Time
	last        time.Time
	recordIndex uint64
	input       uint64
	output      uint64
}

func (c *cursor) open(at time.Time) {
	c.startedAt, c.last = at, at
}

func (c *cursor) started() bool { return !c.startedAt.IsZero() }

func (c *cursor) idle(ro HandlerRecorderObject) bool {
	return ro.InputBytes == c.input && ro.OutputBytes == c.output
}
func (c *cursor) record(ro HandlerRecorderObject, now time.Time, phase, id string) SessionRecord {
	input := max(ro.InputBytes, c.input)
	output := max(ro.OutputBytes, c.output)
	ro.InputBytes, ro.OutputBytes = input, output
	ro.Time = now
	ro.Duration = now.Sub(c.startedAt)

	return SessionRecord{
		HandlerRecorderObject: ro,
		SessionID:             id,
		RecordIndex:           c.recordIndex + 1,
		Phase:                 phase,
		InputBytesDelta:       input - c.input,
		OutputBytesDelta:      output - c.output,
		DurationDelta:         now.Sub(c.last),
	}
}

func (c *cursor) commit(record SessionRecord) {
	c.input, c.output = record.InputBytes, record.OutputBytes
	c.recordIndex = record.RecordIndex
	c.last = record.Time
}
