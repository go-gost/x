// Package loader provides interfaces and implementations for hot-reloadable
// data sources used by components such as auth, bypass, hosts, and admission.
package loader

import (
	"context"
	"io"
)

// Loader loads data from a backend source, returning it as an io.Reader.
type Loader interface {
	Load(context.Context) (io.Reader, error)
	Close() error
}

// Lister lists entries from a backend source.
type Lister interface {
	List(ctx context.Context) ([]string, error)
}

// Mapper loads key-value pairs from a backend source.
type Mapper interface {
	Map(ctx context.Context) (map[string]string, error)
}
