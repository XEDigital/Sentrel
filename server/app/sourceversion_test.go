package app

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pb "sentrel/gen/sentrelv1"
)

// A deb built from a differently versioned source package (libldb2 from samba)
// keeps the source version, and a pending update of it counts as the fix for a
// finding whose fixed version is a source version.
func TestPackageSourceVersion(t *testing.T) {
	e := newTestEnv(t)
	admin := e.setupAdmin()
	ctx := context.Background()
	h, _ := e.enrol(admin)
	hi, _ := json.Marshal(map[string]any{"os": "linux", "arch": "amd64"})
	if _, err := e.a.db.ExecContext(ctx, `UPDATE hosts SET host_info=? WHERE id=?`, string(hi), h); err != nil {
		t.Fatal(err)
	}
	invHash := func() string {
		var s string
		_ = e.a.db.GetContext(ctx, &s, `SELECT value FROM settings WHERE tenant_id=0 AND key=?`, "invhash:"+itoa(h))
		return s
	}
	send := func(installed, upgradable []*pb.Package) {
		e.a.handleAgentMessage(ctx, h, &pb.AgentMessage{Msg: &pb.AgentMessage_Inventory{Inventory: &pb.Inventory{
			TsMs: time.Now().UnixMilli(), PackageManager: "apt", Installed: installed, Upgradable: upgradable}}})
	}
	ldb := func(srcVer string) *pb.Package {
		return &pb.Package{Name: "libldb2", Version: "2:2.6.2+samba4.17.12+dfsg-0+deb12u4", Arch: "amd64", Type: "deb", Source: "samba", SourceVersion: srcVer}
	}

	// An older agent sends no source version.
	send([]*pb.Package{ldb("")}, nil)
	before := invHash()
	// The first inventory with it changes the hash, so the host is rescanned.
	send([]*pb.Package{ldb("2:4.17.12+dfsg-0+deb12u4")}, []*pb.Package{
		{Name: "libldb2", Version: "2:2.6.2+samba4.17.12+dfsg-0+deb12u4", NewVersion: "2:2.6.2+samba4.17.13+dfsg-0+deb12u1", Arch: "amd64", Type: "deb", Source: "bookworm-security", Security: true}})
	if invHash() == before {
		t.Fatal("inventory hash unchanged when the source version appeared")
	}
	var p Package
	if err := e.a.db.GetContext(ctx, &p, `SELECT * FROM packages WHERE host_id=? AND name='libldb2'`, h); err != nil {
		t.Fatal(err)
	}
	if p.SourceVersion != "2:4.17.12+dfsg-0+deb12u4" || p.NewVersion == "" {
		t.Fatalf("stored package: %+v", p)
	}

	// The fix is a samba version; libldb2's own version cannot be compared with it.
	enableVuln(t, e)
	e.addFinding(t, h, "CVE-SAMBA", "libldb2", "2:4.17.13+dfsg-0+deb12u1", "Critical")
	f := e.findings(t, admin, "?host_id="+itoa(h))["CVE-SAMBA"]
	if !f.Upgradable || f.Remediation != remUpgrade {
		t.Fatalf("finding not upgradable through the pending update: %+v", f)
	}
}
