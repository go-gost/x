package dns

// resolvConfPath is unused on Windows — systemNameservers never reads a file
// here — but it stays declared so tests that redirect it (to exercise the
// Init fallback chain) compile on every platform.
var resolvConfPath string

// systemNameservers returns nil on Windows because reading the system DNS
// configuration requires the Windows IP Helper API. Callers should fall
// back to the hardcoded default when this returns nil.
func systemNameservers() []string {
	return nil
}
