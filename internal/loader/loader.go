package loader

import (
	"context"
	"io"
)

type Loader interface {
	Load(context.Context) (io.Reader, error)
	Close() error
}

type Lister interface {
	List(ctx context.Context) ([]string, error)
}

type Mapper interface {
	Map(ctx context.Context) (map[string]string, error)
}
