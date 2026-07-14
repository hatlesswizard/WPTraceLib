package wptracelib

import (
	"context"
	"strings"
	"testing"
)

func TestFetchPluginListRejectsNegativeMaxPlugins(t *testing.T) {
	lib := New(Config{MaxPlugins: -1})
	_, err := lib.FetchPluginList(context.Background())
	if err == nil || !strings.Contains(err.Error(), "MaxPlugins cannot be negative") {
		t.Fatalf("error = %v, want clear negative MaxPlugins error", err)
	}
}
