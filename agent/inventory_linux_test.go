//go:build linux

package agent

import "testing"

func TestParseDpkgQuery(t *testing.T) {
	out := "ii \tlibldb2:amd64\t2:2.6.2+samba4.17.12+dfsg-0+deb12u4\tamd64\tsamba\t2:4.17.12+dfsg-0+deb12u4\n" +
		"ii \tcurl\t7.88.1-10+deb12u15\tamd64\tcurl\t7.88.1-10+deb12u15\n" +
		"rc \told-thing\t1.0\tamd64\told-thing\t1.0\n" +
		"ii \tlegacy\t1.0\tall\t\n"
	got := parseDpkgQuery([]byte(out))
	if len(got) != 3 {
		t.Fatalf("packages: %+v", got)
	}
	if p := got[0]; p.Name != "libldb2" || p.Source != "samba" || p.SourceVersion != "2:4.17.12+dfsg-0+deb12u4" {
		t.Errorf("libldb2: %+v", p)
	}
	if p := got[1]; p.Source != "curl" || p.SourceVersion != "" {
		t.Errorf("curl: source version kept although equal: %+v", p)
	}
	// Older output without the source version column; empty source is the name.
	if p := got[2]; p.Name != "legacy" || p.Source != "legacy" || p.SourceVersion != "" {
		t.Errorf("legacy: %+v", p)
	}
}
