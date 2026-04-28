// Package exit defines the interface used by the tunnel server to dial
// out to target hosts on behalf of clients, and provides the Direct
// implementation that simply uses net.Dial.
//
// The interface exists so future modes (a headless-Chromium "browser exit"
// for CAPTCHA-protected sites, a residential-proxy chained exit, etc.)
// can plug in without changing the SOCKS handler.
package exit

import (
	"context"
	"errors"
	"net"
	"time"
)

// Dialer dials out from the tunnel server to a target.
type Dialer interface {
	// DialContext dials addr ("host:port"). host may be a domain or IP literal.
	// The returned conn is a raw TCP-like conn the SOCKS handler will splice
	// to the inner stream.
	DialContext(ctx context.Context, addr string) (net.Conn, error)
}

// Direct is the default Dialer: a plain net.Dialer with reasonable timeouts.
type Direct struct {
	Timeout time.Duration
}

// NewDirect returns a Direct dialer.
func NewDirect() *Direct { return &Direct{Timeout: 10 * time.Second} }

// DialContext implements Dialer.
func (d *Direct) DialContext(ctx context.Context, addr string) (net.Conn, error) {
	if addr == "" {
		return nil, errors.New("exit: empty addr")
	}
	nd := &net.Dialer{Timeout: d.Timeout, KeepAlive: 30 * time.Second}
	return nd.DialContext(ctx, "tcp", addr)
}
