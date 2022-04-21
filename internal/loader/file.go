package loader

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
)

type fileLoader struct {
	filename string
}

// FileLoader loads data from file.
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

// List implements Lister interface{}
func (l *fileLoader) List(ctx context.Context) (list []string, err error) {
	f, err := os.Open(l.filename)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		list = append(list, scanner.Text())
	}
	err = scanner.Err()

	return
}

func (l *fileLoader) Close() error {
	return nil
}
