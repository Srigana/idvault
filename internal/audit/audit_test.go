package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainAndTamper(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.log")
	l, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{"snapshot.create", "restore.execute", "snapshot.delete"} {
		if err := l.Record("amehta", a, "x", "ok", ""); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := l.Verify(); err != nil || n != 3 {
		t.Fatalf("verify: %d %v", n, err)
	}
	l.Close()

	b, _ := os.ReadFile(p)
	_ = os.WriteFile(p, []byte(strings.Replace(string(b), `"actor":"amehta","action":"snapshot.delete"`, `"actor":"kasante","action":"snapshot.delete"`, 1)), 0o600)
	if _, err := Open(p); err == nil {
		t.Fatal("edited log must fail to open")
	}

	lines := strings.SplitAfter(string(b), "\n")
	_ = os.WriteFile(p, []byte(lines[0]+lines[2]), 0o600) // delete the middle entry
	if _, err := Open(p); err == nil {
		t.Fatal("deleted entry must be detected")
	}
}
