// Command pmt-probe verifies that domain fronting from a given front
// (SNI) to a given worker host (Host header) still works on the current
// network path. It is meant to be run BEFORE deploying the tunnel so
// that the most fragile assumption in the design (GFE accepting a
// mismatched SNI / Host) is empirically validated.
//
// Usage:
//
//	pmt-probe \
//	  --front www.google.com \
//	  --front-ip 216.239.38.120 \
//	  --worker my-svc-abc.run.app \
//	  --path /healthz
//
// Exit codes:
//
//	0  fronting works (worker responded with the expected status)
//	1  TLS handshake or HTTP failed
//	2  worker returned an unexpected status (likely GFE intercepted)
//	3  bad usage
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"golang.org/x/net/http2"

	"github.com/easyfast2008/PMT-DFC/internal/dialer"
)

func main() {
	front := flag.String("front", "www.google.com", "front SNI domain")
	frontIP := flag.String("front-ip", "", "fixed IP for front (skip DNS); recommended")
	frontPort := flag.Int("front-port", 443, "front port")
	worker := flag.String("worker", "", "worker host (Host header)")
	path := flag.String("path", "/healthz", "path to GET on the worker")
	expect := flag.Int("expect", 200, "expected HTTP status code")
	timeout := flag.Duration("timeout", 15*time.Second, "overall probe timeout")
	flag.Parse()

	if *worker == "" {
		fmt.Fprintln(os.Stderr, "missing --worker")
		os.Exit(3)
	}

	d, err := dialer.New(dialer.Config{
		FrontDomain: *front,
		FrontIP:    *frontIP,
		Port:       *frontPort,
	})
	if err != nil {
		fail(1, "dialer: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	t0 := time.Now()
	tlsConn, err := d.DialContext(ctx)
	if err != nil {
		fail(1, "tls: %v", err)
	}
	defer tlsConn.Close()
	tlsT := time.Since(t0)
	cs := tlsConn.ConnectionState()

	tr := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return nil, errors.New("unexpected dial")
		},
	}
	cc, err := tr.NewClientConn(tlsConn)
	if err != nil {
		fail(1, "h2 client conn: %v", err)
	}

	u := &url.URL{Scheme: "https", Host: *worker, Path: *path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		fail(1, "request: %v", err)
	}
	req.Host = *worker
	req.Header.Set("User-Agent", "pmt-probe/0.1")

	t1 := time.Now()
	resp, err := cc.RoundTrip(req)
	if err != nil {
		fail(1, "round trip: %v", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	resp.Body.Close()

	fmt.Printf("front     = %s (%s)\n", *front, *frontIP)
	fmt.Printf("worker    = %s\n", *worker)
	fmt.Printf("alpn      = %s\n", cs.NegotiatedProtocol)
	fmt.Printf("tls       = %s (%s, cert=%s)\n", tlsT.Round(time.Millisecond), tls.VersionName(cs.Version), shorten(cs.PeerCertificates[0].Subject.String()))
	fmt.Printf("http      = %s -> %d (%s)\n", time.Since(t1).Round(time.Millisecond), resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Printf("body[0:80]= %q\n", trim(body, 80))

	if resp.StatusCode != *expect {
		fmt.Println()
		fmt.Println("FRONTING DID NOT REACH WORKER:")
		fmt.Printf("  got status %d, expected %d\n", resp.StatusCode, *expect)
		fmt.Println("  GFE most likely intercepted the request before routing by Host.")
		os.Exit(2)
	}
	fmt.Println("\nOK: fronting reached the worker successfully.")
}

func fail(code int, format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(code)
}

func shorten(s string) string {
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

func trim(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
