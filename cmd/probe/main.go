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
  all        Runs tcp → tls → front → cross → runapp for one --front.
  sweep      Same as all, but iterates over multiple --front values
             (comma-separated via --fronts=a,b,c). Prints a matrix.
  targets    Probes whether GFE will route fronted requests to each Google
             L7 product family (Cloud Run, App Engine, Cloud Functions,
             Firebase Hosting, googleusercontent, googleapis). Classifies
             each response as ROUTED / BLOCKED-GEO / NOT-FOUND / INTERCEPTED.
             Use this when --mode=runapp returns 403 — to find a sibling
             product GFE will route to instead.
  worker     Probes a real deployed worker (--worker host required).

Examples:
  pmt-probe --mode=all   --front=www.google.com
  pmt-probe --mode=all   --front=www.google.com --front-ip=216.239.38.120
  pmt-probe --mode=sweep --front-ip=216.239.38.120 \
            --fronts=www.google.com,mail.google.com,drive.google.com
  pmt-probe --mode=worker --front=www.google.com --worker=svc-abc.run.app

`
)

// defaultSweepFronts is the list seeded from real-world deployments
// (Google login subdomains tend to be permitted by most filtering
// stacks because blocking them breaks Workspace, school accounts, etc.).
// Override on the command line with --fronts.
var defaultSweepFronts = []string{
	"www.google.com",
	"mail.google.com",
	"drive.google.com",
	"docs.google.com",
	"calendar.google.com",
	"accounts.google.com",
	"scholar.google.com",
	"maps.google.com",
	"chat.google.com",
	"translate.google.com",
	"play.google.com",
	"lens.google.com",
	"chromewebstore.google.com",
}

func main() {
	mode := flag.String("mode", "all", "tcp|tls|front|cross|runapp|worker|all|sweep|targets")
	front := flag.String("front", "www.google.com", "front domain (SNI)")
	fronts := flag.String("fronts", "", "comma-separated SNIs for mode=sweep (default: built-in list)")
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
	case "targets":
		var rb [6]byte
		_, _ = rand.Read(rb[:])
		nonce := hex.EncodeToString(rb[:])
		fmt.Printf("---- target sweep via %s (front_ip=%s) ----\n\n", *front, *frontIP)
		fmt.Printf("%-44s  %-3s  %-12s  %s\n", "product / Host", "code", "verdict", "server")
		fmt.Printf("%-44s  %-3s  %-12s  %s\n", strings.Repeat("-", 44), "----", "------------", "------")
		anyRoutable := false
		for _, t := range defaultTargets {
			h := t.host(nonce)
			status, server, verdict, err := fetchTargetVerdict(*front, *frontIP, *frontPort, h, *timeout)
			label := t.product
			if len(label) > 44 {
				label = label[:41] + "..."
			}
			if err != nil {
				fmt.Printf("%-44s  %-3s  %-12s  err: %v\n", label, "---", "-", err)
				continue
			}
			fmt.Printf("%-44s  %-3d  %-12s  %s\n", label, status, verdict, server)
			if verdict == verdictRouted || verdict == verdictNotFound {
				anyRoutable = true
			}
		}
		fmt.Println()
		if anyRoutable {
			fmt.Println("at least one product family is reachable from this network — pick one and re-target the server side accordingly.")
		} else {
			fmt.Println("every product family was BLOCKED-GEO or INTERCEPTED — Google L7 fronting is dead from this network.")
			code = exitInterc
		}
	case "sweep":
		list := defaultSweepFronts
		if *fronts != "" {
			list = splitCSV(*fronts)
		}
		results := make([]sweepRow, 0, len(list))
		for _, sni := range list {
			fmt.Printf("---- %s ----\n", sni)
			row := sweepRow{sni: sni}
			row.tcp = quiet(func() error { return testTCP(*frontIP, sni, *frontPort, *timeout) })
			row.tls = quiet(func() error { return testTLS(sni, *frontIP, *frontPort, *timeout) })
			row.front = quiet(func() error { return testHTTP(sni, *frontIP, *frontPort, sni, "/", -1, *timeout) })
			row.cross = quiet(func() error {
				return testHTTP(sni, *frontIP, *frontPort, "clients4.google.com", "/generate_204", 204, *timeout)
			})
			row.runapp = quiet(func() error {
				return testRunApp(sni, *frontIP, *frontPort, randomRunApp(), *timeout)
			})
			results = append(results, row)
		}
		fmt.Println()
		fmt.Println("---- sweep matrix ----")
		fmt.Printf("%-30s  %-4s %-4s %-5s %-5s %-6s  %s\n", "SNI", "tcp", "tls", "front", "cross", "runapp", "verdict")
		anyOK := false
		for _, r := range results {
			verdict := "FRONTING WORKS"
			if r.cross != "" || r.runapp != "" {
				verdict = "DO NOT USE"
			}
			if r.tcp != "" || r.tls != "" {
				verdict = "BLOCKED"
			}
			if verdict == "FRONTING WORKS" {
				anyOK = true
			}
			fmt.Printf("%-30s  %-4s %-4s %-5s %-5s %-6s  %s\n",
				r.sni,
				ok(r.tcp), ok(r.tls), ok(r.front), ok(r.cross), ok(r.runapp),
				verdict,
			)
		}
		if !anyOK {
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

// targetSpec is one Google L7 backend product hostname pattern that we
// can probe with a fronted request to see whether GFE will route to it
// from this network. The hostname is constructed at probe time so it
// definitely doesn't exist — we only care whether GFE *would* route the
// request, not whether the backend serves anything.
type targetSpec struct {
	product string                 // human label
	host    func(rand string) string // build the Host header
}

var defaultTargets = []targetSpec{
	{"Cloud Run (run.app)", func(r string) string { return fmt.Sprintf("nonexistent-%s-uc.a.run.app", r) }},
	{"App Engine (appspot.com)", func(r string) string { return fmt.Sprintf("nonexistent-%s.appspot.com", r) }},
	{"App Engine versioned (uc.r.appspot.com)", func(r string) string { return fmt.Sprintf("nonexistent-%s.uc.r.appspot.com", r) }},
	{"Cloud Functions Gen1 (cloudfunctions.net)", func(r string) string { return fmt.Sprintf("us-central1-nonexistent-%s.cloudfunctions.net", r) }},
	{"Firebase Hosting (web.app)", func(r string) string { return fmt.Sprintf("nonexistent-%s.web.app", r) }},
	{"Firebase Hosting (firebaseapp.com)", func(r string) string { return fmt.Sprintf("nonexistent-%s.firebaseapp.com", r) }},
	{"Google user content (googleusercontent.com)", func(r string) string { return fmt.Sprintf("nonexistent-%s.googleusercontent.com", r) }},
	{"Google APIs frontend (storage.googleapis.com)", func(_ string) string { return "storage.googleapis.com" }},
	{"Google APIs frontend (maps.googleapis.com)", func(_ string) string { return "maps.googleapis.com" }},
}

// targetVerdict classifies the response from a fronted GET against an
// L7 product hostname.
type targetVerdict string

const (
	verdictRouted     targetVerdict = "ROUTED"      // backend (or its load balancer) responded — fronting works
	verdictBlockedGeo targetVerdict = "BLOCKED-GEO" // GFE refused with the generic "your client does not have permission" 403
	verdictNotFound   targetVerdict = "NOT-FOUND"   // GFE returned generic 404 — no service registered, but routing path not blocked
	verdictIntercept  targetVerdict = "INTERCEPTED" // GFE served the front HTML — Host header was ignored
	verdictUnknown    targetVerdict = "UNKNOWN"     // anything else
)

// classifyTargetResp inspects a fronted response and returns a verdict.
// Heuristics:
//   - If status==200 AND body contains the front domain text → INTERCEPTED.
//   - If status==403 AND body contains the generic "your client does not have
//     permission" / "Forbidden" robot-page text → BLOCKED-GEO.
//   - If status==404 AND body contains "Page not found" / "The requested URL"
//     and there's no backend-specific marker → NOT-FOUND.
//   - If body or server header has any backend-shaped marker (Cloud Run,
//     App Engine, Cloud Functions, Firebase, GCS, etc.) → ROUTED.
//   - Otherwise → UNKNOWN.
func classifyTargetResp(front string, status int, body []byte, server string) targetVerdict {
	bl := strings.ToLower(string(body))
	sv := strings.ToLower(server)
	frontL := strings.ToLower(front)

	// 1. Definitive BLOCKED-GEO: the generic "Error 403 (Forbidden)!!1" robot
	//    page Google serves when it refuses to route a request. The body always
	//    contains "permission to get URL" — that's the load-bearing string.
	if strings.Contains(bl, "permission to get url") ||
		strings.Contains(bl, "your client does not have permission") {
		return verdictBlockedGeo
	}

	// 2. Definitive INTERCEPT: GFE served the front itself instead of routing.
	if status == 200 && strings.Contains(bl, frontL) && len(bl) > 1000 {
		return verdictIntercept
	}

	// 3. Backend-shaped server header → ROUTED. These are Google internal
	//    frontend identifiers: gws, sffe (static content), ESF (encrypted
	//    storage), GSE, scaffolding on HTTPServer (App Engine), UploadServer
	//    (GCS), Google Frontend, etc. Generic GFE block pages have NO server
	//    header at all, so a non-empty server with one of these markers means
	//    the request reached a real backend.
	backendServerMarkers := []string{
		"google frontend", "scaffolding", "httpserver",
		"uploadserver", "sffe", "gse", "esf", "gws",
	}
	for _, m := range backendServerMarkers {
		if strings.Contains(sv, m) {
			return verdictRouted
		}
	}

	// 4. Body markers naming the product → ROUTED.
	backendBodyMarkers := []string{
		"cloud run", "run.app",
		"google app engine", "appspot",
		"cloud functions",
		"firebase",
		"cloud storage", "googleapis",
	}
	for _, m := range backendBodyMarkers {
		if strings.Contains(bl, m) {
			return verdictRouted
		}
	}

	// 5. Generic GFE 404: "Error: Page not found" / "The requested URL was not
	//    found on this server." These come from GFE itself when no backend is
	//    registered at the Host. NOT a hard block — a real service would
	//    receive the request — so treat as routing-permitted.
	if status == 404 && (strings.Contains(bl, "page not found") ||
		strings.Contains(bl, "requested url was not found")) {
		return verdictNotFound
	}

	// 6. Fall-through. Treat 403 + "forbidden" body as BLOCKED-GEO too (less
	//    specific than rule 1 but catches abbreviated variants).
	if status == 403 && strings.Contains(bl, "forbidden") {
		return verdictBlockedGeo
	}

	return verdictUnknown
}

// fetchTargetVerdict makes one fronted GET and classifies the response.
func fetchTargetVerdict(front, frontIP string, port int, hostHeader string, timeout time.Duration) (int, string, targetVerdict, error) {
	d, err := dialer.New(dialer.Config{FrontDomain: front, FrontIP: frontIP, Port: port, HandshakeTimeout: timeout})
	if err != nil {
		return 0, "", verdictUnknown, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tc, err := d.DialContext(ctx)
	if err != nil {
		return 0, "", verdictUnknown, err
	}
	defer tc.Close()
	tr := &http2.Transport{
		DialTLSContext: func(_ context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			return nil, errors.New("unexpected dial")
		},
	}
	cc, err := tr.NewClientConn(tc)
	if err != nil {
		return 0, "", verdictUnknown, err
	}
	u := &url.URL{Scheme: "https", Host: hostHeader, Path: "/"}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	req.Host = hostHeader
	req.Header.Set("User-Agent", "pmt-probe/0.1")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return 0, "", verdictUnknown, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<14))
	_ = resp.Body.Close()
	server := resp.Header.Get("Server")
	v := classifyTargetResp(front, resp.StatusCode, body, server)
	return resp.StatusCode, server, v, nil
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

type sweepRow struct {
	sni                            string
	tcp, tls, front, cross, runapp string // empty == pass; non-empty == error message
}

// quiet runs fn and returns the error message (or "" on success). Used by
// the sweep mode so we don't double-print per-step results.
func quiet(fn func() error) string {
	if err := fn(); err != nil {
		return err.Error()
	}
	return ""
}

func ok(s string) string {
	if s == "" {
		return "ok"
	}
	return "X"
}

func splitCSV(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func shorten(s string) string {
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
