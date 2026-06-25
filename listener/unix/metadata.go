package unix

import (
	"os"
	"strconv"

	md "github.com/go-gost/core/metadata"
)

type metadata struct {
	fileMode os.FileMode
}

func (l *unixListener) parseMetadata(md md.Metadata) (err error) {
	if !md.IsExists("mode") {
		return
	}

	switch v := md.Get("mode").(type) {
	case int:
		l.md.fileMode = os.FileMode(v)
	case string:
		n, _ := strconv.ParseInt(v, 0, 32)
		l.md.fileMode = os.FileMode(n)
	}
	return
}
