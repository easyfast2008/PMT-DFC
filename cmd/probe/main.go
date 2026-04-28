// Command pmt-probe answers two questions empirically, before you spend
// any money on Cloud Run:
//
//  1. "Is this approach even feasible from MY network?"
//     (modes: tcp, tls, front, cross, runapp, all)
//
//  2. "Is my actually-deployed worker reachable through fronting?"
//     (mode: worker)
//
// You can run the feasibility modes against just `--front www.google.com`
// (and optionally `--front-ip <ip>`); they hit only well-known Google
// endpoints and do not require you to deploy anything.
//
// Exit codes:
//
//	0  the test reported PASS
//	1  network / TLS / HTTP failed before producing a result
//	2  fronting did not reach the intended backend (GFE intercepted)
//	3  bad usage
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"

	"github.com/easyfast2008/PMT-DFC/internal/dialer"
)

const (
	exitOK        = 0
	exitNetwork   = 1
	exitInterc    = 2
	exitBadUsage  = 3
	usageHeadline = `pmt-probe — domain-fronting feasibility & worker probe

Modes:
  tcp        TCP/443 reachability to the front IP/host.
  tls        TLS handshake to the front (SNI = --front), check ALPN + cert.
  front      HTTPS GET to the front itself (sanity: SNI=front, Host=front).
  cross      Cross-origin Host routing: SNI=--front, Host=clients4.google.com.
             A 204 proves GFE still routes by Host across origins.
  runapp     Routing to *.run.app: SNI=--front, Host=<random>.run.app.
             A Cloud Run-style 404 proves Cloud Run is reachable via fronting.
  all        Runs tcp → tls → front → cross → runapp.
  worker     Probes a real deployed worker (--worker host required).

Examples:
  pmt-probe --mode=all --front=www.google.com
  pmt-probe --mode=all --front=www.google.com --front-ip=216.239.38.120
  pmt-probe --mode=worker --front=www.google.com --worker=svc-abc.run.app

`
)

func main() {
	mode := flag.String("mode", "all", "tcp|tls|front|cross|runapp|worker|all")
	front := flag.String("front", "www.google.com", "front domain (SNI)")
	frontIP := flag.String("front-ip", "", "fixed IP for the front (skip DNS); recommended on censored networks")
	frontPort := flag.Int("front-port", 443, "front port")
	worker := flag.String("worker", "", "worker host (Host header) — required for mode=worker")
	path := flag.String("path", "/healthz", "path for mode=worker")
	expect := flag.Int("expect", 200, "expected status for mode=worker")
	timeout := flag.Duration("timeout", 15*time.Second, "per-step timeout")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usageHeadline)
		flag.PrintDefaults()
	}
	flag.Parse()

	out := &report{}

	code := exitOK
	switch *mode {
	case "tcp":
		code = runOne(out, "tcp", func() error { return testTCP(*frontIP, *front, *frontPort, *timeout) })
	case "tls":
		code = runOne(out, "tls", func() error { return testTLS(*front, *frontIP, *frontPort, *timeout) })
	case "front":
		code = runOne(out, "front", func() error { return testHTTP(*front, *frontIP, *frontPort, *front, "/", -1, *timeout) })
	case "cross":
		code = runOne(out, "cross", func() error {
			return testHTTP(*front, *frontIP, *frontPort, "clients4.google.com", "/generate_204", 204, *timeout)
		})
	case "runapp":
		code = runOne(out, "runapp", func() error {
			host := randomRunApp()
			return testRunApp(*front, *frontIP, *frontPort, host, *timeout)
		})
	case "worker":
		if *worker == "" {
			fmt.Fprintln(os.Stderr, "mode=worker requires --worker")
			os.Exit(exitBadUsage)
		}
		code = runOne(out, "worker", func() error {
			return testHTTP(*front, *frontIP, *frontPort, *worker, *path, *expect, *timeout)
		})
	case "all":
		any := false
		any = runStep(out, any, "tcp", func() error { return testTCP(*frontIP, *front, *frontPort, *timeout) })
		any = runStep(out, any, "tls", func() error { return testTLS(*front, *frontIP, *frontPort, *timeout) })
		any = runStep(out, any, "front", func() error { return testHTTP(*front, *frontIP, *frontPort, *front, "/", -1, *timeout) })
		any = runStep(out, any, "cross", func() error {
			return testHTTP(*front, *frontIP, *frontPort, "clients4.google.com", "/generate_204", 204, *timeout)
		})
		any = runStep(out, any, "runapp", func() error {
			host := randomRunApp()
			return testRunApp(*front, *frontIP, *frontPort, host, *timeout)
		})
		if any {
			code = exitInterc
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(exitBadUsage)
	}
	out.flush()
	if code == exitOK {
		fmt.Println("\nfeasible: domain-fronted Cloud Run should work on this network.")
	} else {
		fmt.Println("\nNOT feasible: at least one critical step failed; do not deploy.")
	}
	os.Exit(code)
}

// runOne runs a single test and returns the appropriate exit code.
func runOne(out *report, name string, fn func() error) int {
	if err := fn(); err != nil {
		out.line("[%s] FAIL: %v", name, err)
		return classify(err)
	}
	out.line("[%s] PASS", name)
	return exitOK
}

// runStep runs a single test as part of mode=all. Returns true if any step
// has failed so far. Subsequent failures still run so the user sees the
// whole picture.
func runStep(out *report, hadFail bool, name string, fn func() error) bool {
	if err := fn(); err != nil {
		out.line("[%s] FAIL: %v", name, err)
		return true
	}
	out.line("[%s] PASS", name)
	return hadFail
}

// classify returns exitInterc for fronting interception, exitNetwork otherwise.
func classify(err error) int {
	var ie *interceptError
	if errors.As(err, &ie) {
		return exitInterc
	}
	return exitNetwork
}

// interceptError signals "we got an HTTP response, but it wasn't from the
// backend we tried to address — GFE intercepted the request before
// routing by Host."
type interceptError struct{ s string }

func (e *interceptError) Error() string { return e.s }

func intercept(format string, args ...any) error {
	return &interceptError{s: fmt.Sprintf(format, args...)}
}

func testTCP(frontIP, front string, port int, timeout time.Duration) error {
	addr := front
	if frontIP != "" {
		addr = frontIP
	}
	hostport := net.JoinHostPort(addr, fmt.Sprintf("%d", port))
	t0 := time.Now()
	c, err := net.DialTimeout("tcp", hostport, timeout)
	if err != nil {
		return fmt.Errorf("tcp dial %s: %w", hostport, err)
	}
	c.Close()
	fmt.Printf("       connect: %s (%s)\n", time.Since(t0).Round(time.Millisecond), hostport)
	return nil
}

func testTLS(front, frontIP string, port int, timeout time.Duration) error {
	d, err := dialer.New(dialer.Config{FrontDomain: front, FrontIP: frontIP, Port: port, HandshakeTimeout: timeout})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t0 := time.Now()
	tc, err := d.DialContext(ctx)
	if err != nil {
		return err
	}
	defer tc.Close()
	cs := tc.ConnectionState()
	fmt.Printf("       handshake: %s\n", time.Since(t0).Round(time.Millisecond))
	fmt.Printf("       version  : %s\n", tls.VersionName(cs.Version))
	fmt.Printf("       alpn     : %s\n", cs.NegotiatedProtocol)
	if len(cs.PeerCertificates) > 0 {
		c0 := cs.PeerCertificates[0]
		fmt.Printf("       cert.cn  : %s\n", shorten(c0.Subject.CommonName))
		fmt.Printf("       cert.iss : %s\n", shorten(c0.Issuer.CommonName))
		// Chain verification already happened during the handshake (we use
		// system roots and do NOT skip verify). The CN/Issuer log is a hint
		// for diagnosing surprising results — not a hard gate.
		if !looksGoogleCert(c0.Subject.CommonName, c0.Issuer.CommonName) {
			fmt.Printf("       %s warning: cert subject/issuer does not look like Google's chain — double-check this is the GFE you expected\n", "")
		}
	}
	if cs.NegotiatedProtocol != "h2" {
		return fmt.Errorf("ALPN did not negotiate h2 (got %q)", cs.NegotiatedProtocol)
	}
	return nil
}

func testHTTP(front, frontIP string, port int, hostHeader, path string, expectStatus int, timeout time.Duration) error {
	d, err := dialer.New(dialer.Config{FrontDomain: front, FrontIP: frontIP, Port: port, HandshakeTimeout: timeout})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tc, err := d.DialContext(ctx)
	if err != nil {
		return err
	}
	defer tc.Close()

	tr := &http2.Transport{
		AllowHTTP: false,
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return nil, errors.New("unexpected dial")
		},
	}
	cc, err := tr.NewClientConn(tc)
	if err != nil {
		return fmt.Errorf("h2 client conn: %w", err)
	}
	u := &url.URL{Scheme: "https", Host: hostHeader, Path: path}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Host = hostHeader
	req.Header.Set("User-Agent", "pmt-probe/0.1")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("round trip: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	_ = resp.Body.Close()
	fmt.Printf("       host     : %s\n", hostHeader)
	fmt.Printf("       status   : %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Printf("       server   : %s\n", resp.Header.Get("Server"))
	if expectStatus >= 0 && resp.StatusCode != expectStatus {
		// Did GFE intercept and serve the front itself?
		if hostHeader != front && looksLikeFrontIntercept(resp, body, front) {
			return intercept("expected status %d but got %d, and response body looks like %s — GFE ignored Host header", expectStatus, resp.StatusCode, front)
		}
		return intercept("expected status %d, got %d", expectStatus, resp.StatusCode)
	}
	return nil
}

func testRunApp(front, frontIP string, port int, fakeHost string, timeout time.Duration) error {
	d, err := dialer.New(dialer.Config{FrontDomain: front, FrontIP: frontIP, Port: port, HandshakeTimeout: timeout})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tc, err := d.DialContext(ctx)
	if err != nil {
		return err
	}
	defer tc.Close()

	tr := &http2.Transport{
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return nil, errors.New("unexpected dial")
		},
	}
	cc, err := tr.NewClientConn(tc)
	if err != nil {
		return err
	}
	u := &url.URL{Scheme: "https", Host: fakeHost, Path: "/"}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Host = fakeHost
	req.Header.Set("User-Agent", "pmt-probe/0.1")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return fmt.Errorf("round trip: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	_ = resp.Body.Close()
	srv := resp.Header.Get("Server")
	fmt.Printf("       host     : %s\n", fakeHost)
	fmt.Printf("       status   : %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	fmt.Printf("       server   : %s\n", srv)
	// We expect a 4xx that is clearly Cloud Run / Google Frontend.
	bodyLower := strings.ToLower(string(body))
	cloudRunish := strings.Contains(bodyLower, "cloud run") ||
		strings.Contains(bodyLower, "run.app") ||
		strings.Contains(bodyLower, "the requested url") ||
		strings.Contains(strings.ToLower(srv), "google frontend") ||
		strings.Contains(strings.ToLower(srv), "frontend")
	if resp.StatusCode == 200 && !cloudRunish {
		return intercept("got 200 from a non-existent run.app host — GFE served the front instead of routing to Cloud Run")
	}
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && cloudRunish {
		return nil
	}
	if cloudRunish {
		return nil
	}
	return intercept("response does not look like Cloud Run / Google Frontend (status=%d, server=%q)", resp.StatusCode, srv)
}

func randomRunApp() string {
	var b [6]byte
	_, _ = rand.Read(b[:])
	// `*-uc.a.run.app` is a real Cloud Run hostname pattern that resolves on GFE.
	return fmt.Sprintf("nonexistent-%s-uc.a.run.app", hex.EncodeToString(b[:]))
}

func looksGoogleCert(s string, issuer string) bool {
	// Google's leaf certs are issued by GTS — full names ("Google Trust Services",
	// "GTS CA 1C3") or short codes ("WR2", "WE1"). The chain validates against
	// system roots in the dialer; this helper is purely a UX heuristic.
	is := strings.ToLower(issuer)
	for _, marker := range []string{"google", "gts", "wr1", "wr2", "we1", "we2"} {
		if strings.Contains(is, marker) {
			return true
		}
	}
	cn := strings.ToLower(s)
	for _, want := range []string{"google.com", "googleapis.com", "googleusercontent.com", "gstatic.com", "run.app", "appspot.com"} {
		if strings.Contains(cn, want) {
			return true
		}
	}
	return false
}

// looksLikeFrontIntercept returns true when GFE served the front domain's
// content instead of routing by Host.
func looksLikeFrontIntercept(resp *http.Response, body []byte, front string) bool {
	frontLower := strings.ToLower(front)
	if strings.Contains(strings.ToLower(string(body)), frontLower) && resp.StatusCode == 200 {
		return true
	}
	return false
}

type report struct {
	lines []string
}

func (r *report) line(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *report) flush() {
	if len(r.lines) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("---- summary ----")
	for _, l := range r.lines {
		fmt.Println(l)
	}
}

func shorten(s string) string {
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
