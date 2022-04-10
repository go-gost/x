package loader

import (
	"bytes"
	"context"
	"io"
	"os"
)

type fileLoader struct {
	filename string
}

func FileLoader(filename string) Loader {
	return &fileLoader{
		filename: filename,
	}
}

func (l *fileLoader) Load(ctx context.Context) (io.Reader, error) {
	data, err := os.ReadFile(l.filename)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

func (l *fileLoader) Close() error {
	return nil
}
