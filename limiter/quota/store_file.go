package quota

import (
	"encoding/json"
	"os"
	"sync"
)

// fileStore persists all records into one JSON file. A single instance is shared
// per path so concurrent per-name saves merge instead of clobbering each other.
type fileStore struct {
	path string
	mu   sync.Mutex
	data map[string]Record
}

var fileStores sync.Map // path -> *fileStore

func NewFileStore(path string) Store {
	if v, ok := fileStores.Load(path); ok {
		return v.(*fileStore)
	}
	fs := &fileStore{path: path, data: make(map[string]Record)}
	fs.load()
	actual, _ := fileStores.LoadOrStore(path, fs)
	return actual.(*fileStore)
}

func (fs *fileStore) load() {
	b, err := os.ReadFile(fs.path)
	if err != nil {
		return
	}
	data := make(map[string]Record)
	if json.Unmarshal(b, &data) == nil {
		fs.data = data
	}
}

func (fs *fileStore) Load(name string) (Record, bool, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	rec, ok := fs.data[name]
	return rec, ok, nil
}

func (fs *fileStore) Save(name string, rec Record) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	fs.data[name] = rec
	return fs.writeLocked()
}

func (fs *fileStore) writeLocked() error {
	b, err := json.MarshalIndent(fs.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := fs.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, fs.path)
}
