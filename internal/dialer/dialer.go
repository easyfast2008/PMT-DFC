// Package dialer provides a TCP+TLS dialer that performs SNI domain fronting:
// the outer TLS ClientHello carries SNI=FrontDomain (e.g. "www.google.com"),
// while the inner HTTP Host header targets the real backend (e.g. a Cloud Run
// service hosted on `*.run.app`).
//
// To the firewall the connection is indistinguishable from a TLS connection
// to the front domain. To Google Front End, the Host header determines the
// backend that ultimately receives the request.
//
// This package only handles the L4/L5 part (TCP + TLS). Setting the inner
// Host header is the caller's responsibility.
package dialer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Config configures a Fronting dialer.
type Config struct {
	// FrontDomain is the SNI value sent in the outer TLS ClientHello.
	// The firewall observes this. Example: "www.google.com".
	FrontDomain string

	// FrontIP is an optional fixed IP for the front domain. If set, the
	// dialer skips DNS and dials this IP directly. Useful in environments
	// where DNS is censored or where you want to pin a known-reachable
	// Google IP.
	FrontIP string

	// Port to dial on the front IP/domain. Defaults to 443.
	Port int

	// HandshakeTimeout bounds the TLS handshake.
	HandshakeTimeout time.Duration

	// PreferH1 advertises HTTP/1.1 before h2 in ALPN. Useful for relays
	// where h2 multiplexing is handled at a higher layer.
	PreferH1 bool

	// InsecureSkipVerify disables certificate verification.
	// Only useful for local testing — never set in production.
	InsecureSkipVerify bool

	// RootCAs lets callers pin a specific root pool. Defaults to system roots.
	RootCAs *tls.Config // entire tls.Config used as a template
}

// Dialer dials the front IP/domain and negotiates TLS with SNI=FrontDomain.
type Dialer struct {
	cfg     Config
	netDial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// New returns a Dialer with the given config.
func New(cfg Config) (*Dialer, error) {
	if cfg.FrontDomain == "" {
		return nil, errors.New("dialer: FrontDomain is required")
	}
	if cfg.Port == 0 {
		cfg.Port = 443
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 15 * time.Second
	}
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	return &Dialer{cfg: cfg, netDial: d.DialContext}, nil
}

// DialContext returns a TLS connection to the front. ALPN advertises h2 first.
//
// The returned conn has performed the TLS handshake. The caller can then
// drive HTTP/2 on top of it.
func (d *Dialer) DialContext(ctx context.Context) (*tls.Conn, error) {
	addr := d.cfg.FrontDomain
	if d.cfg.FrontIP != "" {
		addr = d.cfg.FrontIP
	}
	addr = net.JoinHostPort(addr, fmt.Sprintf("%d", d.cfg.Port))

	rawConn, err := d.netDial(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialer: tcp dial %s: %w", addr, err)
	}

	protos := []string{"h2", "http/1.1"}
	if d.cfg.PreferH1 {
		protos = []string{"http/1.1", "h2"}
	}
	tlsCfg := &tls.Config{
		ServerName:         d.cfg.FrontDomain,
		NextProtos:         protos,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: d.cfg.InsecureSkipVerify, //nolint:gosec // documented test escape hatch
	}
	if d.cfg.RootCAs != nil && d.cfg.RootCAs.RootCAs != nil {
		tlsCfg.RootCAs = d.cfg.RootCAs.RootCAs
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	hsCtx, cancel := context.WithTimeout(ctx, d.cfg.HandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("dialer: tls handshake: %w", err)
	}
	got := tlsConn.ConnectionState().NegotiatedProtocol
	if got != "h2" && got != "http/1.1" && got != "" {
		_ = tlsConn.Close()
		return nil, fmt.Errorf("dialer: ALPN negotiated %q, want h2 or http/1.1", got)
	}
	return tlsConn, nil
}
