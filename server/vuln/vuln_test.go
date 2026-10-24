package vuln

import (
	"testing"

	"github.com/anchore/grype/grype/distro"
)

func TestGrypePackagesUpstreamVersion(t *testing.T) {
	d := distro.NewFromNameVersion("debian", "12")
	got := grypePackages(d, []Package{
		{Name: "libldb2", Version: "2:2.6.2+samba4.17.12+dfsg-0+deb12u4", Type: "deb", Source: "samba", SourceVersion: "2:4.17.12+dfsg-0+deb12u4"},
		{Name: "libcurl4", Version: "7.88.1-10+deb12u15", Type: "deb", Source: "curl"},
		{Name: "bash", Version: "5.2.15-2+b8", Type: "deb", Source: "bash", SourceVersion: "5.2.15-2"},
		{Name: "openssl-libs", Version: "1:3.0.7-27.el9", Type: "rpm", Source: "openssl-3.0.7-27.el9.src.rpm", SourceVersion: "ignored"},
	})
	if len(got) != 4 {
		t.Fatalf("packages: %d", len(got))
	}
	up := func(i int) (string, string) {
		if len(got[i].Upstreams) != 1 {
			t.Fatalf("%s upstreams: %+v", got[i].Name, got[i].Upstreams)
		}
		return got[i].Upstreams[0].Name, got[i].Upstreams[0].Version
	}
	// The source version is what Debian's data is keyed by.
	if n, v := up(0); n != "samba" || v != "2:4.17.12+dfsg-0+deb12u4" {
		t.Errorf("libldb2 upstream = %s %s", n, v)
	}
	// Unknown source version: Grype falls back to the binary version.
	if n, v := up(1); n != "curl" || v != "" {
		t.Errorf("libcurl4 upstream = %s %s", n, v)
	}
	// Same-named source: matched directly, no upstream.
	if len(got[2].Upstreams) != 0 {
		t.Errorf("bash upstreams: %+v", got[2].Upstreams)
	}
	// rpm: the source rpm name only.
	if n, v := up(3); n != "openssl" || v != "" {
		t.Errorf("openssl-libs upstream = %s %s", n, v)
	}
}
