// test/main.go regenerates the checked-in .pcap fixtures and their sha256
// manifests (testdata/fixtures.sha256 next to each fixture directory).
//
//	go run ./test
//
// The generator is deterministic (see testgenpcap.Epoch), so a no-change run
// is a no-op on disk and `git status` stays clean; a scenario edit rewrites
// the file and its manifest line together.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"go.peanball.net/cap/internal/testgenpcap"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "genpcap: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	for dir, names := range testgenpcap.Dirs() {
		var lines []string
		for _, name := range names {
			data, err := testgenpcap.Generate(dir, name)
			if err != nil {
				return err
			}
			path := filepath.Join(dir, name)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			if old, err := os.ReadFile(path); err == nil && sha256.Sum256(old) == sum {
				lines = append(lines, fmt.Sprintf("%x  %s", sum, name))
				continue
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				return err
			}
			lines = append(lines, fmt.Sprintf("%x  %s", sum, name))
			fmt.Printf("wrote %s (%d bytes)\n", path, len(data))
		}
		sort.Strings(lines)
		manifest := []byte(fmt.Sprintf("# sha256 of each fixture, as written by go run ./test.\n%s\n", joinLines(lines)))
		mPath := filepath.Join(dir, testgenpcap.ManifestName)
		if old, err := os.ReadFile(mPath); err == nil && string(old) == string(manifest) {
			continue
		}
		if err := os.WriteFile(mPath, manifest, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", mPath)
	}
	return nil
}

func joinLines(ls []string) string {
	out := ""
	for _, l := range ls {
		out += l + "\n"
	}
	return out
}
