package selector

import (
	"os"
	"testing"

	corelogger "github.com/go-gost/core/logger"
	xlogger "github.com/go-gost/x/logger"
)

func TestMain(m *testing.M) {
	corelogger.SetDefault(xlogger.Nop())
	os.Exit(m.Run())
}
