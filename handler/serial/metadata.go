package serial

import (
	"time"

	mdata "github.com/go-gost/core/metadata"
	mdutil "github.com/go-gost/x/metadata/util"
)

// metadata holds the parsed configuration for the serial handler.
// It is populated from the handler's metadata map during Init().
type metadata struct {
	// timeout is the per-read timeout applied when opening a serial port
	// directly (not through the router chain). It controls how long the
	// serial port blocks waiting for data before returning to the caller.
	// A value of 0 means blocking indefinitely (no timeout).
	timeout time.Duration
}

// parseMetadata extracts typed configuration from the generic metadata map.
// Supported keys: "timeout", "serial.timeout" (both accept duration strings
// like "5s" or integer seconds).
func (h *serialHandler) parseMetadata(md mdata.Metadata) (err error) {
	h.md.timeout = mdutil.GetDuration(md, "timeout", "serial.timeout")
	return
}
