// Package icewarp is a client for the IceWarp admin RPC API (the XML-over-HTTP
// "admin:iq:rpc" interface), wrapping net/http and encoding/xml. It exposes the
// operations the LDAP bridge needs: a service-account session, user password
// validation, account search, per-account property read/write, password
// write-back, and account create/delete.
//
// See docs/icewarp-api.md for the wire reference this is built against.
package icewarp

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

const rpcNamespace = "admin:iq:rpc"

// APIError is a server-returned error, identified by its uid (see the error-uid
// catalogue in docs/icewarp-api.md).
type APIError struct {
	UID     string
	Command string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("icewarp: command %q failed: %s", e.Command, e.UID)
}

// Sentinel errors for the bind path (GetAuthToken), mapped from API errors so
// callers don't switch on uids.
var (
	// ErrInvalidCredentials is returned for a wrong password, unknown account
	// or unknown domain — the API does not distinguish these (no enumeration).
	// Note: this failure is tarpitted ~25-30s server-side.
	ErrInvalidCredentials = errors.New("icewarp: invalid credentials")
	// ErrAccountDisabled is returned when the password is correct but the
	// account is disabled. This failure is immediate (not tarpitted).
	ErrAccountDisabled = errors.New("icewarp: account disabled")
)

// Client talks to a single IceWarp admin RPC endpoint as one service account.
// It is safe for concurrent use; the cached session id is guarded by a mutex
// and refreshed automatically on session_invalid.
type Client struct {
	endpoint string
	email    string
	password string
	http     *http.Client
	logger   *slog.Logger

	// introspectDir, when non-empty, is a directory each RPC body is dumped to.
	introspectDir string

	mu  sync.Mutex
	sid string
}

// Option configures a Client.
type Option func(*Client)

// WithLogger sets the logger. At debug level every RPC call is logged as a
// single line (operation, HTTP status, duration). For the full request/response
// bodies use WithIntrospection. If nil, logging is discarded.
func WithLogger(l *slog.Logger) Option {
	return func(c *Client) {
		if l != nil {
			c.logger = l
		}
	}
}

// WithIntrospection enables dumping the full, raw body of every RPC request and
// response to dir, one file per body named
// "<UTC-datetime>-<operation>-<req|res>.log" (<password> elements redacted).
// It is independent of the log level and is intended for local debugging only —
// it is verbose and writes credentials-adjacent payloads to disk.
func WithIntrospection(dir string) Option {
	return func(c *Client) { c.introspectDir = dir }
}

// NewClient returns a client for endpoint (e.g.
// "http://icewarp:80/icewarpapi/") authenticating as email/password.
func NewClient(endpoint, email, password string, opts ...Option) *Client {
	c := &Client{
		endpoint: endpoint,
		email:    email,
		password: password,
		// Timeout is longer than the largest repo-level context timeout (repoBindTimeout=90s)
		// so the context always fires first; this is defense-in-depth for callers that
		// forget a deadline.
		http:   &http.Client{Timeout: 120 * time.Second},
		logger: slog.New(slog.DiscardHandler),
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.introspectDir != "" {
		if err := os.MkdirAll(c.introspectDir, 0o700); err != nil {
			c.logger.Warn("icewarp introspection disabled: cannot create dir", "dir", c.introspectDir, "err", err)
			c.introspectDir = ""
		}
	}
	return c
}

// call sends one command and decodes the <result> payload into result (which
// may be nil). sid is attached to the request when non-empty. It returns the
// session id from the response <iq> (set by authenticate) and any error.
func (c *Client) call(ctx context.Context, sid, command string, params, result any) (string, error) {
	body, err := buildRequest(sid, command, params)
	if err != nil {
		return "", fmt.Errorf("icewarp: build %s request: %w", command, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")

	start := time.Now()
	c.introspect(start, command, "req", body)

	resp, err := c.http.Do(req)
	if err != nil {
		c.logger.Debug("icewarp call", "command", command, "dur", time.Since(start), "err", err)
		return "", fmt.Errorf("icewarp: %s request: %w", command, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MiB hard cap
	if err != nil {
		c.logger.Debug("icewarp call", "command", command, "status", resp.StatusCode, "dur", time.Since(start), "err", err)
		return "", fmt.Errorf("icewarp: read %s response: %w", command, err)
	}
	c.introspect(start, command, "res", raw)
	c.logger.Debug("icewarp call", "command", command, "status", resp.StatusCode, "dur", time.Since(start))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("icewarp: %s: http %d", command, resp.StatusCode)
	}

	var env struct {
		Type  string `xml:"type,attr"`
		SID   string `xml:"sid,attr"`
		Query struct {
			Inner []byte `xml:",innerxml"`
		} `xml:"query"`
	}
	if err := xml.Unmarshal(raw, &env); err != nil {
		return "", fmt.Errorf("icewarp: decode %s response: %w", command, err)
	}

	if env.Type == "error" {
		var ae struct {
			UID string `xml:"uid,attr"`
		}
		_ = xml.Unmarshal(env.Query.Inner, &ae)
		return env.SID, &APIError{UID: ae.UID, Command: command}
	}

	if result != nil {
		if err := xml.Unmarshal(env.Query.Inner, result); err != nil {
			return env.SID, fmt.Errorf("icewarp: decode %s result: %w", command, err)
		}
	}
	return env.SID, nil
}

// sessionCall runs a session command using the cached sid, authenticating first
// if needed and retrying once on session_invalid (per the docs' guidance).
func (c *Client) sessionCall(ctx context.Context, command string, params, result any) error {
	sid, err := c.session(ctx)
	if err != nil {
		return err
	}

	_, err = c.call(ctx, sid, command, params, result)
	if !isSessionInvalid(err) {
		return err
	}

	// Session expired/invalid: re-authenticate and retry once.
	if err := c.Authenticate(ctx); err != nil {
		return err
	}
	sid, err = c.session(ctx)
	if err != nil {
		return err
	}
	_, err = c.call(ctx, sid, command, params, result)
	return err
}

// session returns the cached sid, authenticating if none is held yet.
func (c *Client) session(ctx context.Context) (string, error) {
	c.mu.Lock()
	sid := c.sid
	c.mu.Unlock()
	if sid != "" {
		return sid, nil
	}
	if err := c.Authenticate(ctx); err != nil {
		return "", err
	}
	c.mu.Lock()
	sid = c.sid
	c.mu.Unlock()
	return sid, nil
}

func isSessionInvalid(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.UID == "session_invalid"
}

// passwordRE matches the contents of a <password> element so debug logs don't
// leak admin or user passwords carried in request/response bodies.
var passwordRE = regexp.MustCompile(`(<password>)[^<]*(</password>)`)

// redactPasswords returns body as a string with any <password> contents masked.
func redactPasswords(body []byte) string {
	return string(passwordRE.ReplaceAll(body, []byte("${1}***${2}")))
}

// introspect dumps one RPC body to the introspection dir (no-op when disabled).
// req and res of the same call share the start timestamp so they sort and pair.
func (c *Client) introspect(start time.Time, command, kind string, body []byte) {
	if c.introspectDir == "" {
		return
	}
	name := fmt.Sprintf("%s-%s-%s.log", start.UTC().Format("20060102T150405.000000000"), command, kind)
	if err := os.WriteFile(filepath.Join(c.introspectDir, name), []byte(redactPasswords(body)), 0o600); err != nil {
		c.logger.Warn("icewarp introspection write failed", "file", name, "err", err)
	}
}

// buildRequest assembles the <iq><query>…</query></iq> envelope. The params
// value must marshal to a <commandparams> element (or be nil for none). The
// envelope is written by hand to guarantee the exact, mandatory namespace.
func buildRequest(sid, command string, params any) ([]byte, error) {
	var paramsXML []byte
	if params != nil {
		b, err := xml.Marshal(params)
		if err != nil {
			return nil, err
		}
		paramsXML = b
	} else {
		paramsXML = []byte("<commandparams></commandparams>")
	}

	var buf bytes.Buffer
	buf.WriteString("<iq")
	if sid != "" {
		buf.WriteString(` sid="`)
		_ = xml.EscapeText(&buf, []byte(sid))
		buf.WriteString(`"`)
	}
	buf.WriteString(`><query xmlns="` + rpcNamespace + `"><commandname>`)
	buf.WriteString(command)
	buf.WriteString("</commandname>")
	buf.Write(paramsXML)
	buf.WriteString("</query></iq>")
	return buf.Bytes(), nil
}
