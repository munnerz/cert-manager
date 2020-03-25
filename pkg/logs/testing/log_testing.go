package testing

import (
	"testing"

	"github.com/go-logr/logr"
)

// TestLogger is a logr.Logger that prints through a testing.T object.
type TestLogger struct {
	T *testing.T
}

var _ logr.Logger = TestLogger{}

func (_ TestLogger) Enabled() bool {
	return true
}

func (log TestLogger) Info(msg string, args ...interface{}) {
	log.T.Logf("%s: %v", msg, args)
}

func (log TestLogger) Error(err error, msg string, args ...interface{}) {
	log.T.Logf("%s: %v -- %v", msg, err, args)
}

func (log TestLogger) V(v int) logr.InfoLogger {
	return log
}

func (log TestLogger) WithName(_ string) logr.Logger {
	return log
}

func (log TestLogger) WithValues(_ ...interface{}) logr.Logger {
	return log
}
