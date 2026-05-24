// Package metadata provides the default implementation of the core/metadata.Metadata
// interface using a map[string]any with case-insensitive keys.
package metadata

import (
	"strings"

	"github.com/go-gost/core/metadata"
)

type mapMetadata map[string]any

// NewMetadata creates a new Metadata from the given map. Keys are lowercased for
// case-insensitive lookup. If m is nil, an empty Metadata is returned.
func NewMetadata(m map[string]any) metadata.Metadata {
	md := make(map[string]any)
	for k, v := range m {
		md[strings.ToLower(k)] = v
	}
	return mapMetadata(md)
}

// IsExists reports whether the key is present in the metadata.
func (m mapMetadata) IsExists(key string) bool {
	_, ok := m[strings.ToLower(key)]
	return ok
}

// Set stores a value for the given key.
func (m mapMetadata) Set(key string, value any) {
	m[strings.ToLower(key)] = value
}

// Get retrieves the value for the given key, or nil if the key is not present.
func (m mapMetadata) Get(key string) any {
	if m != nil {
		return m[strings.ToLower(key)]
	}
	return nil
}
