// Package agentdist serves agent binaries: embedded in the server at build
// time, or from a directory override.
package agentdist

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

//go:embed bin
var embedded embed.FS

// Binary is one agent build.
type Binary struct {
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Name    string `json:"name"`
	open    func() (io.ReadCloser, error)
}

// Open returns the binary contents.
func (b *Binary) Open() (io.ReadCloser, error) { return b.open() }

// FileName is the canonical file name for os/arch.
func FileName(goos, goarch string) string {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return "sentrel-agent-linux-amd64"
	case "linux/arm64":
		return "sentrel-agent-linux-arm64"
	case "windows/amd64":
		return "sentrel-agent-windows-amd64.exe"
	default:
		return ""
	}
}

var (
	mu    sync.Mutex
	cache = map[string]*Binary{}
)

// ErrNotFound means no binary exists for the platform.
var ErrNotFound = errors.New("agent binary not available for this platform")

// Get returns the binary for os/arch, preferring dir when set.
func Get(dir, goos, goarch string) (*Binary, error) {
	name := FileName(goos, goarch)
	if name == "" {
		return nil, fmt.Errorf("%w: %s/%s", ErrNotFound, goos, goarch)
	}
	key := dir + "|" + name
	mu.Lock()
	defer mu.Unlock()
	if dir != "" {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err == nil {
			if b, ok := cache[key]; ok && b.Size == fi.Size() {
				return b, nil
			}
			sum, err := fileHash(p)
			if err != nil {
				return nil, err
			}
			ver := readVersion(os.DirFS(dir))
			b := &Binary{OS: goos, Arch: goarch, Version: ver, SHA256: sum, Size: fi.Size(), Name: name,
				open: func() (io.ReadCloser, error) { return os.Open(p) }}
			cache[key] = b
			return b, nil
		}
	}
	if b, ok := cache["embed|"+name]; ok {
		return b, nil
	}
	data, err := embedded.ReadFile("bin/" + name)
	if err != nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrNotFound, goos, goarch)
	}
	sub, _ := fs.Sub(embedded, "bin")
	s := sha256.Sum256(data)
	b := &Binary{OS: goos, Arch: goarch, Version: readVersion(sub), SHA256: hex.EncodeToString(s[:]), Size: int64(len(data)), Name: name,
		open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil }}
	cache["embed|"+name] = b
	return b, nil
}

// List returns all available binaries.
func List(dir string) []*Binary {
	var out []*Binary
	for _, p := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}} {
		if b, err := Get(dir, p[0], p[1]); err == nil {
			out = append(out, b)
		}
	}
	return out
}

func readVersion(fsys fs.FS) string {
	b, err := fs.ReadFile(fsys, "VERSION")
	if err != nil {
		return "unknown"
	}
	// Release builds write the tag ("v0.9.6"); agents report the version
	// without the "v" ("0.9.6"). Use the agents' form so the two compare equal.
	return strings.TrimPrefix(strings.TrimSpace(string(b)), "v")
}

func fileHash(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
