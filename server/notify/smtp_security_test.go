package notify

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/textproto"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSMTPMessageCannotInjectHeaders(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	messages := make(chan string, 1)
	failures := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			failures <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		rd := textproto.NewReader(bufio.NewReader(conn))
		if _, err := fmt.Fprint(conn, "220 audit.local ESMTP\r\n"); err != nil {
			failures <- err
			return
		}
		for {
			line, err := rd.ReadLine()
			if err != nil {
				failures <- err
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"), strings.HasPrefix(line, "MAIL FROM:"), strings.HasPrefix(line, "RCPT TO:"):
				_, err = fmt.Fprint(conn, "250 audit.local\r\n")
			case line == "DATA":
				_, err = fmt.Fprint(conn, "354 send data\r\n")
				if err != nil {
					failures <- err
					return
				}
				body, readErr := io.ReadAll(rd.DotReader())
				if readErr != nil {
					failures <- readErr
					return
				}
				messages <- string(body)
				_, err = fmt.Fprint(conn, "250 accepted\r\n")
			case line == "QUIT":
				_, _ = fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				failures <- fmt.Errorf("unexpected SMTP command: %q", line)
				return
			}
			if err != nil {
				failures <- err
				return
			}
		}
	}()
	host, portText, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	text := `<script>alert("injected")</script>`
	m := msg()
	m.Subject = "disk\r\nBcc: attacker@example.com"
	m.Items[0].Title = text
	m.Items[0].Message = text
	if err := SendMail(context.Background(), SMTP{Host: host, Port: port, From: "alerts@example.com", TLSMode: "none"}, []string{"recipient@example.com"}, m.Subject, text, renderHTML(m)); err != nil {
		t.Fatal(err)
	}
	select {
	case wire := <-messages:
		parsed, err := mail.ReadMessage(strings.NewReader(wire))
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Header.Get("Bcc") != "" {
			t.Fatal("SMTP header injection reached the wire")
		}
		if !strings.Contains(parsed.Header.Get("Subject"), "Bcc:") {
			t.Fatal("sanitized subject text was lost")
		}
		if strings.Contains(wire, "<script>") { // text/plain may contain this; only inspect HTML independently below.
			if html := renderHTML(m); strings.Contains(html, "<script>") || !strings.Contains(html, "&lt;script&gt;") {
				t.Fatalf("unescaped alert HTML: %s", html)
			}
		}
	case err := <-failures:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("SMTP capture timed out")
	}
}
