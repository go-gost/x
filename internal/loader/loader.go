package loader

import (
	"context"
	"io"
)

type Loader interface {
	Load(context.Context) (io.Reader, error)
	Close() error
}
