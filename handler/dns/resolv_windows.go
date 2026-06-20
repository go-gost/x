package dns

// systemNameservers returns nil on Windows because reading the system DNS
// configuration requires the Windows IP Helper API. Callers should fall
// back to the hardcoded default when this returns nil.
func systemNameservers() []string {
	return nil
}
