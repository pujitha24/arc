package storage

import (
	"context"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"testing"
)

func TestLicensePreparedNamespaceIsNotRediscovered(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{"db/events/one.parquet", ".arc-license-oss/node/2/storage/db/events/one.parquet"} {
		p := filepath.Join(root, filepath.FromSlash(rel))
		os.MkdirAll(filepath.Dir(p), 0700)
		if err := os.WriteFile(p, []byte("data"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	b, err := NewLocalBackend(root, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	files, err := b.List(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "db/events/one.parquet" {
		t.Fatalf("rediscovered prepared copies: %v", files)
	}
	if omittedFromListing("one.parquet", ".arc-license-oss-other/db/one.parquet") != nil {
		t.Fatal("reserved prefix matched sibling")
	}
}
