package quota

type Record struct {
	Used      uint64 `json:"used"`
	Limit     uint64 `json:"limit"`
	StartsAt  int64  `json:"startsAt"`  // unixnano; 0 = unset
	ExpiresAt int64  `json:"expiresAt"` // unixnano; 0 = unset
	UpdatedAt int64  `json:"updatedAt"`
}

// Store persists per-name quota records. Implementations must be concurrency-safe.
type Store interface {
	// Load returns ok=false when no record exists yet.
	Load(name string) (rec Record, ok bool, err error)
	Save(name string, rec Record) error
}
