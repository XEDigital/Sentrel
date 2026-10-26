package metrics

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestLabelsCannotAliasReservedIdentity(t *testing.T) {
	s, err := Open(t.TempDir(), 24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	now := time.Now()
	err = s.Append(11, 22, []Sample{{Name: "cpu_usage_percent", Labels: map[string]string{"host.id": "999", "tenant.id": "999", "__name__": "evil", "device.name": "sda", "device-name": "sdb"}, Value: 42, TsMs: now.UnixMilli()}})
	if err != nil {
		t.Fatalf("must accept sample safely: %v", err)
	}
	out, err := s.QueryInstant(context.Background(), `sentrel_cpu_usage_percent{host_id="11",tenant_id="22"}`, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("lost canonical host/tenant identity: %+v", out)
	}
	if out[0].Labels["host_id"] != "11" || out[0].Labels["tenant_id"] != "22" {
		t.Fatalf("identity spoofed: %+v", out)
	}
}
