// Package notify delivers alert notifications to external services.
package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"sentrel/server/netguard"
)

// Item is one alert in a (possibly grouped) notification.
type Item struct {
	AlertID    int64    `json:"alert_id"`
	Event      string   `json:"event"`  // fired, resolved, escalated, flapping, reminder, test
	Status     string   `json:"status"` // firing, resolved
	Severity   string   `json:"severity"`
	Title      string   `json:"title"`
	Message    string   `json:"message"`
	Host       string   `json:"host"`
	HostID     int64    `json:"host_id"`
	Tenant     string   `json:"tenant"`
	Value      *float64 `json:"value"`
	Threshold  *float64 `json:"threshold"`
	StartedAt  int64    `json:"started_at"`
	ResolvedAt int64    `json:"resolved_at"`
	URL        string   `json:"url"`
	Acked      bool     `json:"acked"`
}

// Message is what gets sent to one channel.
type Message struct {
	Subject  string `json:"subject"`
	Status   string `json:"status"` // firing, resolved, mixed
	Severity string `json:"severity"`
	Items    []Item `json:"alerts"`
	URL      string `json:"url"`
	Product  string `json:"product"`
	SentAt   int64  `json:"sent_at"`
}

// SMTP holds relay settings for email channels.
type SMTP struct {
	Host       string
	Port       int
	Username   string
	Password   string
	From       string
	TLSMode    string // starttls, tls, none
	SkipVerify bool
}

// Config is the union of channel settings.
type Config struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Headers     map[string]string `json:"headers"`
	Template    string            `json:"template"` // generic webhook body template
	ContentType string            `json:"content_type"`
	BotToken    string            `json:"bot_token"` // telegram
	ChatID      string            `json:"chat_id"`   // telegram
	Topic       string            `json:"topic"`     // ntfy
	Server      string            `json:"server"`    // ntfy, gotify
	Token       string            `json:"token"`     // ntfy access token, gotify app token, pushover app token
	UserKey     string            `json:"user_key"`  // pushover
	Priority    int               `json:"priority"`
	To          []string          `json:"to"` // email
	SkipVerify  bool              `json:"skip_verify"`
	Username    string            `json:"username"` // webhook basic auth / discord display name
	Password    string            `json:"password"`

	guard netguard.Guard // set by Send; the zero value is the strict tenant policy
}

// Secret field names stripped by the API on read.
var SecretFields = []string{"bot_token", "token", "user_key", "password"}

// Types lists the supported channel types.
var Types = []string{"webhook", "discord", "slack", "teams", "telegram", "ntfy", "gotify", "pushover", "email"}

// Send delivers msg via the given channel type.
func Send(ctx context.Context, g netguard.Guard, typ string, raw json.RawMessage, smtpCfg SMTP, msg Message) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	c.guard = g
	msg.SentAt = time.Now().Unix()
	switch typ {
	case "webhook":
		return sendWebhook(ctx, c, msg)
	case "discord":
		return sendDiscord(ctx, c, msg)
	case "slack":
		return sendSlack(ctx, c, msg)
	case "teams":
		return sendTeams(ctx, c, msg)
	case "telegram":
		return sendTelegram(ctx, c, msg)
	case "ntfy":
		return sendNtfy(ctx, c, msg)
	case "gotify":
		return sendGotify(ctx, c, msg)
	case "pushover":
		return sendPushover(ctx, c, msg)
	case "email":
		return sendEmail(ctx, c, smtpCfg, msg)
	}
	return fmt.Errorf("unknown channel type %q", typ)
}

// Validate checks required fields for a channel type.
func Validate(typ string, raw json.RawMessage) error {
	var c Config
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &c); err != nil {
			return err
		}
	}
	need := func(v, name string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("%s is required", name)
		}
		return nil
	}
	switch typ {
	case "webhook", "discord", "slack", "teams":
		if err := need(c.URL, "url"); err != nil {
			return err
		}
		u, err := url.Parse(c.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("url must be http(s)")
		}
		if c.Template != "" {
			if _, err := template.New("t").Funcs(funcs).Parse(c.Template); err != nil {
				return fmt.Errorf("template: %w", err)
			}
		}
	case "telegram":
		if err := need(c.BotToken, "bot_token"); err != nil {
			return err
		}
		return need(c.ChatID, "chat_id")
	case "ntfy":
		return need(c.Topic, "topic")
	case "gotify":
		if err := need(c.Server, "server"); err != nil {
			return err
		}
		return need(c.Token, "token")
	case "pushover":
		if err := need(c.Token, "token"); err != nil {
			return err
		}
		return need(c.UserKey, "user_key")
	case "email":
		if len(c.To) == 0 {
			return errors.New("at least one recipient is required")
		}
	default:
		return fmt.Errorf("unknown channel type %q", typ)
	}
	return nil
}

func post(ctx context.Context, c Config, method, u, contentType string, body []byte, headers map[string]string) error {
	if method == "" {
		method = http.MethodPost
	}
	req, err := http.NewRequestWithContext(ctx, method, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "Sentrel-Notifier/1")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.Username != "" && c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	tr := c.guard.Transport(&http.Transport{})
	if c.SkipVerify {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	defer tr.CloseIdleConnections()
	cl := &http.Client{Timeout: 20 * time.Second, Transport: tr}
	resp, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	return nil
}

func postJSON(ctx context.Context, c Config, u string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return post(ctx, c, http.MethodPost, u, "application/json", b, c.Headers)
}

var funcs = template.FuncMap{
	"json": func(v any) string {
		b, _ := json.Marshal(v)
		return string(b)
	},
	"upper": strings.ToUpper,
	"lower": strings.ToLower,
	"time": func(ts int64) string {
		if ts == 0 {
			return ""
		}
		return time.Unix(ts, 0).UTC().Format(time.RFC3339)
	},
	"value": func(v *float64) string {
		if v == nil {
			return ""
		}
		return strconv.FormatFloat(*v, 'f', -1, 64)
	},
}

// RenderTemplate renders a webhook body template (exported for previews).
func RenderTemplate(tpl string, msg Message) (string, error) {
	t, err := template.New("t").Funcs(funcs).Parse(tpl)
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	if err := t.Execute(&b, msg); err != nil {
		return "", err
	}
	return b.String(), nil
}

func sendWebhook(ctx context.Context, c Config, msg Message) error {
	if c.Template == "" {
		return postJSON(ctx, c, c.URL, msg)
	}
	body, err := RenderTemplate(c.Template, msg)
	if err != nil {
		return err
	}
	ct := c.ContentType
	if ct == "" {
		ct = "application/json"
	}
	return post(ctx, c, c.Method, c.URL, ct, []byte(body), c.Headers)
}

func emoji(it Item) string {
	if it.Status == "resolved" {
		return "✅"
	}
	switch it.Event {
	case "flapping":
		return "🔁"
	case "test":
		return "🧪"
	}
	if it.Severity == "critical" {
		return "🔴"
	}
	return "🟠"
}

func color(it Item) int {
	if it.Status == "resolved" {
		return 0x16a34a
	}
	if it.Event == "test" {
		return 0x2563eb
	}
	if it.Severity == "critical" {
		return 0xdc2626
	}
	return 0xf59e0b
}

func itemLine(it Item) string {
	s := emoji(it) + " " + it.Title
	if it.Message != "" {
		s += " — " + it.Message
	}
	if it.Event == "escalated" {
		s += " (escalated)"
	}
	if it.Event == "reminder" {
		s += " (still firing)"
	}
	if it.Event == "flapping" {
		s += " (flapping: notifications paused)"
	}
	return s
}

// PlainText renders a message as text.
func PlainText(msg Message) string {
	var b strings.Builder
	b.WriteString(msg.Subject + "\n\n")
	for _, it := range msg.Items {
		b.WriteString(itemLine(it) + "\n")
		if it.URL != "" {
			b.WriteString("  " + it.URL + "\n")
		}
	}
	return b.String()
}

func sendDiscord(ctx context.Context, c Config, msg Message) error {
	var embeds []map[string]any
	for i, it := range msg.Items {
		if i == 10 {
			break
		}
		e := map[string]any{
			"title":       truncate(emoji(it)+" "+it.Title, 250),
			"description": truncate(it.Message, 2000),
			"color":       color(it),
			"timestamp":   time.Unix(msg.SentAt, 0).UTC().Format(time.RFC3339),
		}
		if it.URL != "" {
			e["url"] = it.URL
		}
		fields := []map[string]any{{"name": "Status", "value": strings.ToUpper(it.Status) + eventSuffix(it), "inline": true}, {"name": "Severity", "value": it.Severity, "inline": true}}
		if it.Host != "" {
			fields = append(fields, map[string]any{"name": "Host", "value": it.Host, "inline": true})
		}
		e["fields"] = fields
		embeds = append(embeds, e)
	}
	body := map[string]any{"content": truncate(msg.Subject, 1900), "embeds": embeds}
	if c.Username != "" {
		body["username"] = c.Username
	}
	return postJSON(ctx, Config{Headers: c.Headers, guard: c.guard}, c.URL, body)
}

func eventSuffix(it Item) string {
	switch it.Event {
	case "escalated", "reminder", "flapping", "test":
		return " (" + it.Event + ")"
	}
	return ""
}

func sendSlack(ctx context.Context, c Config, msg Message) error {
	var atts []map[string]any
	for _, it := range msg.Items {
		a := map[string]any{
			"color":  fmt.Sprintf("#%06x", color(it)),
			"title":  emoji(it) + " " + it.Title,
			"text":   it.Message,
			"footer": it.Host,
			"ts":     msg.SentAt,
		}
		if it.URL != "" {
			a["title_link"] = it.URL
		}
		atts = append(atts, a)
	}
	return postJSON(ctx, c, c.URL, map[string]any{"text": msg.Subject, "attachments": atts})
}

func sendTeams(ctx context.Context, c Config, msg Message) error {
	// Adaptive card, accepted by Teams Workflows ("Post to a channel when a
	// webhook request is received") and legacy incoming webhooks.
	body := []map[string]any{{"type": "TextBlock", "size": "Large", "weight": "Bolder", "text": msg.Subject, "wrap": true}}
	for _, it := range msg.Items {
		colorName := "Warning"
		if it.Status == "resolved" {
			colorName = "Good"
		} else if it.Severity == "critical" {
			colorName = "Attention"
		}
		body = append(body,
			map[string]any{"type": "TextBlock", "text": emoji(it) + " " + it.Title, "weight": "Bolder", "color": colorName, "wrap": true, "spacing": "Medium"},
			map[string]any{"type": "TextBlock", "text": it.Message, "wrap": true, "isSubtle": true},
		)
	}
	card := map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4", "body": body}
	if msg.URL != "" {
		card["actions"] = []map[string]any{{"type": "Action.OpenUrl", "title": "Open " + msg.Product, "url": msg.URL}}
	}
	return postJSON(ctx, c, c.URL, map[string]any{
		"type":        "message",
		"attachments": []map[string]any{{"contentType": "application/vnd.microsoft.card.adaptive", "content": card}},
	})
}

func sendTelegram(ctx context.Context, c Config, msg Message) error {
	var b strings.Builder
	b.WriteString("<b>" + html.EscapeString(msg.Subject) + "</b>\n")
	for _, it := range msg.Items {
		b.WriteString("\n" + emoji(it) + " <b>" + html.EscapeString(it.Title) + "</b>\n" + html.EscapeString(it.Message))
		if it.URL != "" {
			b.WriteString("\n<a href=\"" + html.EscapeString(it.URL) + "\">Open</a>")
		}
		b.WriteString("\n")
	}
	base := "https://api.telegram.org"
	if c.Server != "" {
		base = strings.TrimRight(c.Server, "/")
	}
	u := base + "/bot" + c.BotToken + "/sendMessage"
	return postJSON(ctx, Config{guard: c.guard}, u, map[string]any{"chat_id": c.ChatID, "text": truncate(b.String(), 4000), "parse_mode": "HTML", "disable_web_page_preview": true})
}

func sendNtfy(ctx context.Context, c Config, msg Message) error {
	server := c.Server
	if server == "" {
		server = "https://ntfy.sh"
	}
	h := map[string]string{"Title": msg.Subject}
	prio := c.Priority
	if prio == 0 {
		prio = 3
		if msg.Severity == "critical" && msg.Status != "resolved" {
			prio = 5
		}
		if msg.Status == "resolved" {
			prio = 2
		}
	}
	h["Priority"] = strconv.Itoa(prio)
	tag := "warning"
	if msg.Status == "resolved" {
		tag = "white_check_mark"
	} else if msg.Severity == "critical" {
		tag = "rotating_light"
	}
	h["Tags"] = tag
	if msg.URL != "" {
		h["Click"] = msg.URL
	}
	if c.Token != "" {
		h["Authorization"] = "Bearer " + c.Token
	}
	var lines []string
	for _, it := range msg.Items {
		lines = append(lines, itemLine(it))
	}
	return post(ctx, c, http.MethodPost, strings.TrimRight(server, "/")+"/"+url.PathEscape(c.Topic), "text/plain; charset=utf-8", []byte(strings.Join(lines, "\n")), h)
}

func sendGotify(ctx context.Context, c Config, msg Message) error {
	prio := c.Priority
	if prio == 0 {
		prio = 5
		if msg.Severity == "critical" && msg.Status != "resolved" {
			prio = 8
		}
	}
	var lines []string
	for _, it := range msg.Items {
		lines = append(lines, itemLine(it))
	}
	u := strings.TrimRight(c.Server, "/") + "/message?token=" + url.QueryEscape(c.Token)
	body := map[string]any{"title": msg.Subject, "message": strings.Join(lines, "\n"), "priority": prio}
	if msg.URL != "" {
		body["extras"] = map[string]any{"client::notification": map[string]any{"click": map[string]any{"url": msg.URL}}}
	}
	return postJSON(ctx, Config{SkipVerify: c.SkipVerify, guard: c.guard}, u, body)
}

func sendPushover(ctx context.Context, c Config, msg Message) error {
	var lines []string
	for _, it := range msg.Items {
		lines = append(lines, itemLine(it))
	}
	form := url.Values{}
	form.Set("token", c.Token)
	form.Set("user", c.UserKey)
	form.Set("title", truncate(msg.Subject, 250))
	form.Set("message", truncate(strings.Join(lines, "\n"), 1000))
	prio := c.Priority
	if prio == 0 && msg.Severity == "critical" && msg.Status != "resolved" {
		prio = 1
	}
	form.Set("priority", strconv.Itoa(prio))
	if msg.URL != "" {
		form.Set("url", msg.URL)
	}
	u := "https://api.pushover.net/1/messages.json"
	if c.Server != "" {
		u = c.Server
	}
	return post(ctx, Config{guard: c.guard}, http.MethodPost, u, "application/x-www-form-urlencoded", []byte(form.Encode()), nil)
}

func sendEmail(ctx context.Context, c Config, s SMTP, msg Message) error {
	if s.Host == "" {
		return errors.New("SMTP is not configured (Settings → Email)")
	}
	return SendMail(ctx, s, c.To, msg.Subject, PlainText(msg), renderHTML(msg))
}

func renderHTML(msg Message) string {
	var b strings.Builder
	b.WriteString(`<div style="font-family:system-ui,Segoe UI,Arial,sans-serif;max-width:640px">`)
	b.WriteString(`<h2 style="margin:0 0 12px">` + html.EscapeString(msg.Subject) + `</h2>`)
	for _, it := range msg.Items {
		b.WriteString(fmt.Sprintf(`<div style="border-left:4px solid #%06x;padding:8px 12px;margin:8px 0;background:#f8fafc">`, color(it)))
		b.WriteString(`<div style="font-weight:600">` + html.EscapeString(emoji(it)+" "+it.Title) + `</div>`)
		b.WriteString(`<div style="color:#475569">` + html.EscapeString(it.Message) + `</div>`)
		if it.URL != "" {
			b.WriteString(`<div><a href="` + html.EscapeString(it.URL) + `">View in ` + html.EscapeString(msg.Product) + `</a></div>`)
		}
		b.WriteString(`</div>`)
	}
	b.WriteString(`</div>`)
	return b.String()
}

// SendMail sends a multipart text+HTML email through the relay.
func SendMail(ctx context.Context, s SMTP, to []string, subject, text, htmlBody string) error {
	if len(to) == 0 {
		return errors.New("no recipients")
	}
	// Display names and recipients are copied into RFC 5322 headers below.
	// Reject newlines before even connecting, including display-name injection
	// that addrOnly would hide from net/smtp's envelope validation.
	for _, value := range append([]string{s.From, s.Username}, to...) {
		if strings.ContainsAny(value, "\r\n") {
			return errors.New("invalid mail header: address contains a newline")
		}
	}
	port := s.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(s.Host, strconv.Itoa(port))
	tlsCfg := &tls.Config{ServerName: s.Host, InsecureSkipVerify: s.SkipVerify}
	d := net.Dialer{Timeout: 15 * time.Second}
	var conn net.Conn
	var err error
	if s.TLSMode == "tls" {
		conn, err = tls.DialWithDialer(&d, "tcp", addr, tlsCfg)
	} else {
		conn, err = d.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	cl, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if s.TLSMode == "starttls" || s.TLSMode == "" {
		if ok, _ := cl.Extension("STARTTLS"); ok {
			if err := cl.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("starttls: %w", err)
			}
		} else if s.TLSMode == "starttls" {
			return errors.New("server does not support STARTTLS")
		}
	}
	if s.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", s.Username, s.Password, s.Host)); err != nil {
			return fmt.Errorf("auth: %w", err)
		}
	}
	from := s.From
	if from == "" {
		from = s.Username
	}
	if err := cl.Mail(addrOnly(from)); err != nil {
		return err
	}
	for _, r := range to {
		if err := cl.Rcpt(addrOnly(r)); err != nil {
			return fmt.Errorf("rcpt %s: %w", r, err)
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	var parts bytes.Buffer
	mw := multipart.NewWriter(&parts)
	tp, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/plain; charset=utf-8"}})
	tp.Write([]byte(text))
	hp, _ := mw.CreatePart(textproto.MIMEHeader{"Content-Type": {"text/html; charset=utf-8"}})
	hp.Write([]byte(htmlBody))
	mw.Close()
	hdr := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=%s\r\n\r\n",
		from, strings.Join(to, ", "), mimeHeader(subject), time.Now().Format(time.RFC1123Z), mw.Boundary())
	if _, err := w.Write(append([]byte(hdr), parts.Bytes()...)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func addrOnly(s string) string {
	if i := strings.LastIndex(s, "<"); i >= 0 {
		if j := strings.LastIndex(s, ">"); j > i {
			return s[i+1 : j]
		}
	}
	return strings.TrimSpace(s)
}

func mimeHeader(s string) string {
	// Alert subjects include monitored host names and other untrusted text.
	// A subject must stay one header even when its text contains controls.
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	for _, r := range s {
		if r > 127 {
			return "=?UTF-8?B?" + b64(s) + "?="
		}
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
