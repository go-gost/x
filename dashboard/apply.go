package dashboard

import "github.com/go-gost/x/config"

// Apply synchronizes the dashboard with cfg. It enables or disables the
// collector and clears stale series on every call, so removed services and
// obsolete serviceSeen latches do not survive a config reload.
func Apply(cfg *config.Config) {
	on := cfg != nil && cfg.Dashboard != nil && cfg.Dashboard.Enabled
	Enable(on)
	if on {
		Default().Reset()
	}
}
