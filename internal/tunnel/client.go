package tunnel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/auth"
	"github.com/easyfast2008/PMT-DFC/internal/dialer"
	"github.com/hashicorp/yamux"
	"golang.org/x/net/http2"
)

// ClientConfig configures a tunnel Client.
type ClientConfig struct {
	// Dialer dials the front IP and performs the outer TLS handshake.
	Dialer *dialer.Dialer

	// WorkerHost is the inner Host header (e.g. "your-svc-abc123.run.app").
	WorkerHost string

	// Path on the worker that serves the tunnel handler. Defaults to "/tunnel".
	Path string

	// Signer produces auth tokens for each new carrier connection.
	Signer *auth.Signer

	// ReconnectBackoffMin and ReconnectBackoffMax bound the exponential
	// backoff between failed reconnects.
	ReconnectBackoffMin time.Duration
	ReconnectBackoffMax time.Duration

	// KeepalivePeriod sets yamux's application-level ping interval; useful for
	// detecting a silently-dropped carrier (GFE idle timeout). Defaults to 30s.
	KeepalivePeriod time.Duration

	// Logger receives status messages. May be nil.
	Logger func(format string, args ...any)
}

// Client maintains a single live yamux carrier connection and exposes Open
// to launch new tunneled streams. It auto-reconnects on carrier loss.
type Client struct {
	cfg ClientConfig

	mu      sync.Mutex
	session atomic.Pointer[yamux.Session]
	wakeup  chan struct{} // signaled when a new session is ready
	closed  atomic.Bool
}

// NewClient returns a Client that has not yet connected. Call Run on a
// background goroutine to start carrier maintenance.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.Dialer == nil {
		return nil, errors.New("tunnel: ClientConfig.Dialer required")
	}
	if cfg.WorkerHost == "" {
		return nil, errors.New("tunnel: ClientConfig.WorkerHost required")
	}
	if cfg.Signer == nil {
		return nil, errors.New("tunnel: ClientConfig.Signer required")
	}
	if cfg.Path == "" {
		cfg.Path = "/tunnel"
	}
	if cfg.ReconnectBackoffMin <= 0 {
		cfg.ReconnectBackoffMin = 500 * time.Millisecond
	}
	if cfg.ReconnectBackoffMax <= 0 {
		cfg.ReconnectBackoffMax = 30 * time.Second
	}
	if cfg.KeepalivePeriod <= 0 {
		cfg.KeepalivePeriod = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = func(string, ...any) {}
	}
	return &Client{cfg: cfg, wakeup: make(chan struct{}, 1)}, nil
}

// Run blocks until ctx is done, maintaining a live carrier with backoff.
func (c *Client) Run(ctx context.Context) error {
	backoff := c.cfg.ReconnectBackoffMin
	for {
		if c.closed.Load() {
			return nil
		}
		sess, err := c.connect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.cfg.Logger("tunnel: connect failed: %v (backoff %s)", err, backoff)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > c.cfg.ReconnectBackoffMax {
				backoff = c.cfg.ReconnectBackoffMax
			}
			continue
		}
		backoff = c.cfg.ReconnectBackoffMin
		c.cfg.Logger("tunnel: carrier established")
		c.session.Store(sess)
		select {
		case c.wakeup <- struct{}{}:
		default:
		}
		// Block until the session dies.
		<-sess.CloseChan()
		c.session.Store(nil)
		c.cfg.Logger("tunnel: carrier closed; reconnecting")
	}
}

// Close tears down the client. Run will return after the next iteration.
func (c *Client) Close() error {
	c.closed.Store(true)
	if s := c.session.Load(); s != nil {
		_ = s.Close()
	}
	return nil
}

// Open returns a new yamux stream over the live carrier, blocking up to
// timeout for the carrier to come up (or come back) if necessary.
func (c *Client) Open(ctx context.Context) (*yamux.Stream, error) {
	for {
		if s := c.session.Load(); s != nil {
			stream, err := s.OpenStream()
			if err == nil {
				return stream, nil
			}
			// Session is dead; fall through to wait for replacement.
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.wakeup:
		case <-time.After(200 * time.Millisecond):
		}
	}
}

func (c *Client) connect(ctx context.Context) (*yamux.Session, error) {
	tlsConn, err := c.cfg.Dialer.DialContext(ctx)
	if err != nil {
		return nil, err
	}

	// Drive a single HTTP/2 connection on this exact TLS conn. We cannot
	// use http2.Transport's own dialer because we need to control the TLS
	// dial precisely (SNI=front, but the http2 framing peer is GFE).
	transport := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			// Should not be called: we hand the existing tlsConn to a single
			// ClientConn below.
			return nil, errors.New("tunnel: unexpected DialTLSContext invocation")
		},
	}
	cc, err := transport.NewClientConn(tlsConn)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tunnel: new h2 client conn: %w", err)
	}

	pr, pw := io.Pipe()
	u := &url.URL{Scheme: "https", Host: c.cfg.WorkerHost, Path: c.cfg.Path}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), pr)
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	tok, err := c.cfg.Signer.Token()
	if err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	req.Header.Set(auth.Header, tok)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; PMT/0.1)")
	// Critical: set Host so GFE routes by inner Host while SNI was the front.
	req.Host = c.cfg.WorkerHost

	resp, err := cc.RoundTrip(req)
	if err != nil {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tunnel: round trip: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		_ = tlsConn.Close()
		return nil, fmt.Errorf("tunnel: server returned %s", resp.Status)
	}

	conn := &duplexHTTP2{
		r:      resp.Body,
		w:      pw,
		closer: closerFunc(func() error { _ = pw.Close(); return tlsConn.Close() }),
	}
	cfg := yamux.DefaultConfig()
	cfg.KeepAliveInterval = c.cfg.KeepalivePeriod
	cfg.LogOutput = io.Discard
	sess, err := yamux.Client(conn, cfg)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: yamux client: %w", err)
	}
	return sess, nil
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
