package testgenpcap

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestFixturesFresh is the anti-drift gate. It pins three views of every
// fixture to one sha256: what the generator produces now, the file checked
// into testdata/, and the manifest line committed beside it. A change to any
// one without the other two fails here; regenerating with `go run ./test`
// (which rewrites file and manifest together) restores green.
func TestFixturesFresh(t *testing.T) {
	repo := repoRoot(t)
	for dir, names := range Dirs() {
		manifest, err := readManifest(filepath.Join(repo, dir, ManifestName))
		if err != nil {
			t.Fatalf("%s: %v (run `go run ./test`)", dir, err)
		}
		for _, name := range names {
			t.Run(dir+"/"+name, func(t *testing.T) {
				want := manifest[name]
				if want == "" {
					t.Fatalf("%s missing from %s (run `go run ./test`)", name, ManifestName)
				}
				data, err := Generate(dir, name)
				if err != nil {
					t.Fatal(err)
				}
				got := fmt.Sprintf("%x", sha256.Sum256(data))
				if got != want {
					t.Errorf("generator output drifted from manifest\n  generated: %s\n  manifest:  %s\nrun `go run ./test` to regenerate file and manifest", got, want)
				}
				file, err := os.ReadFile(filepath.Join(repo, dir, name))
				if err != nil {
					t.Fatalf("%s missing: %v (run `go run ./test`)", name, err)
				}
				gotFile := fmt.Sprintf("%x", sha256.Sum256(file))
				if gotFile != want {
					t.Errorf("checked-in file drifted from manifest\n  file:      %s\n  manifest:  %s\nrun `go run ./test` to regenerate file and manifest", gotFile, want)
				}
			})
		}
	}
}

// repoRoot walks up from the test's working directory (the package dir) until
// it finds go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above package dir")
		}
		dir = parent
	}
}

// readManifest parses a fixtures.sha256 file of "<hex>  <name>" lines into
// name→hex.
func readManifest(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			return nil, fmt.Errorf("%s: malformed line %q", path, line)
		}
		out[parts[1]] = parts[0]
	}
	return out, s.Err()
}
