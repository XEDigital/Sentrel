package agentdist

import (
	"errors"
	"testing"
)

func TestPlatformPathsAreFixedAllowlist(t *testing.T) {
	for _, p := range [][2]string{{"../../etc", "passwd"}, {"linux", "../../secret"}, {"linux/..", "amd64"}, {"windows", "arm64"}} {
		if name := FileName(p[0], p[1]); name != "" {
			t.Fatalf("untrusted platform produced filename: %q", name)
		}
		if _, err := Get(t.TempDir(), p[0], p[1]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("platform accepted: %v", err)
		}
	}
	for _, p := range [][3]string{{"linux", "amd64", "sentrel-agent-linux-amd64"}, {"linux", "arm64", "sentrel-agent-linux-arm64"}, {"windows", "amd64", "sentrel-agent-windows-amd64.exe"}} {
		if got := FileName(p[0], p[1]); got != p[2] {
			t.Fatalf("platform name: %q", got)
		}
	}
}
