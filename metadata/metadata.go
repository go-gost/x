package metadata

import (
	"github.com/go-gost/core/metadata"
)

type mapMetadata map[string]any

func NewMetadata(m map[string]any) metadata.Metadata {
	return mapMetadata(m)
}

func (m mapMetadata) IsExists(key string) bool {
	_, ok := m[key]
	return ok
}

func (m mapMetadata) Set(key string, value any) {
	m[key] = value
}

func (m mapMetadata) Get(key string) any {
	if m != nil {
		return m[key]
	}
	return nil
}
