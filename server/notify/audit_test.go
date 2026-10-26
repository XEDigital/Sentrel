package notify

import (
	"context"
	"strings"
	"testing"
)

func TestMailHeadersRejectInjection(t *testing.T) {
	for _, subject := range []string{"disk\r\nBcc: attacker@example.com", "disk\nX-Injected: yes", "disk\rX-Injected: yes"} {
		if got := mimeHeader(subject); strings.ContainsAny(got, "\r\n") {
			t.Errorf("header injection survives encoding: %q", got)
		}
	}
	for _, tc := range []struct {
		from string
		to   []string
	}{
		{"Operator\r\nBcc: attacker@example.com <alerts@example.com>", []string{"user@example.com"}},
		{"alerts@example.com", []string{"User\r\nBcc: attacker@example.com <user@example.com>"}},
	} {
		err := SendMail(context.Background(), SMTP{Host: "127.0.0.1", Port: 1, From: tc.from}, tc.to, "subject", "body", "body")
		if err == nil || !strings.Contains(err.Error(), "mail header") {
			t.Errorf("must reject header before dialing: %v", err)
		}
	}
}
