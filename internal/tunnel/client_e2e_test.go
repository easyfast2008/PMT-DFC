package tunnel_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/auth"
	"github.com/easyfast2008/PMT-DFC/internal/dialer"
	"github.com/easyfast2008/PMT-DFC/internal/exit"
	"github.com/easyfast2008/PMT-DFC/internal/socks"
	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// Test_TunnelClient_Roundtrip stands up a real httptest TLS+H2 server and
// drives it through the production tunnel.Client (with InsecureSkipVerify
// so the test cert is accepted). This proves that the dialer, auth signer,
// HTTP/2 transport, and yamux client all integrate correctly without a
// real Cloud Run target.
func Test_TunnelClient_Roundtrip(t *testing.T) {
	psk := []byte("integration-test-psk-16-bytes-or-more")
	verifier := auth.NewVerifier(psk, 1024)

	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoListener.Close()
	go runEcho(echoListener)

	streamHandler := func(stream *yamux.Stream) {
		defer stream.Close()
		req, err := socks.ServeHandshake(stream)
		if err != nil {
			return
		}
		target, err := exit.NewDirect().DialContext(context.Background(), req.Addr)
		if err != nil {
			_ = socks.WriteReply(stream, socks.CodeFromError(err))
			return
		}
		if err := socks.WriteReply(stream, socks.ReplySuccess); err != nil {
			_ = target.Close()
			return
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _, _ = io.Copy(stream, target); _ = stream.Close() }()
		go func() { defer wg.Done(); _, _ = io.Copy(target, stream); _ = target.Close() }()
		wg.Wait()
	}

	mux := http.NewServeMux()
	mux.Handle("/tunnel", tunnel.ServerHandler(verifier, streamHandler))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	host, port, err := splitHostPort(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	d, err := dialer.New(dialer.Config{
		FrontDomain:        "example.com", // SNI value (irrelevant for httptest cert)
		FrontIP:            host,
		Port:               port,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tc, err := tunnel.NewClient(tunnel.ClientConfig{
		Dialer:     d,
		WorkerHost: "example.com",
		Path:       "/tunnel",
		Signer:     auth.NewSigner(psk),
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan struct{})
	go func() {
		_ = tc.Run(ctx)
		close(runDone)
	}()
	t.Cleanup(func() { _ = tc.Close(); <-runDone })

	openCtx, ocancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer ocancel()
	stream, err := tc.Open(openCtx)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(stream, method); err != nil {
		t.Fatal(err)
	}
	if method[1] != 0 {
		t.Fatalf("bad method %v", method)
	}
	hostStr, portStr, _ := net.SplitHostPort(echoListener.Addr().String())
	var portNum uint16
	_, _ = parseUint16(portStr, &portNum)
	body := []byte{5, 1, 0, 3, byte(len(hostStr))}
	body = append(body, []byte(hostStr)...)
	body = binary.BigEndian.AppendUint16(body, portNum)
	if _, err := stream.Write(body); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatal(err)
	}
	if reply[1] != 0 {
		t.Fatalf("connect failed: %v", reply)
	}
	want := []byte("ping-pong")
	if _, err := stream.Write(want); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(want))
	if _, err := io.ReadFull(stream, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch: %q", got)
	}

	_ = stream.Close()
}

// We need to disable H2 ALPN-only verification — httptest's cert is RSA
// and the client uses a TLS dialer that requires h2 ALPN. Rely on
// httptest's negotiation.
var _ = tls.VersionTLS12

func splitHostPort(rawURL string) (string, int, error) {
	u, err := parseRawURL(rawURL)
	if err != nil {
		return "", 0, err
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return "", 0, err
	}
	var pn uint16
	if _, err := parseUint16(port, &pn); err != nil {
		return "", 0, err
	}
	return host, int(pn), nil
}

// minimal URL parse to avoid an extra import in tests
func parseRawURL(s string) (*urlParts, error) {
	const httpsPrefix = "https://"
	if len(s) <= len(httpsPrefix) || s[:len(httpsPrefix)] != httpsPrefix {
		return nil, errors.New("expected https:// URL")
	}
	host := s[len(httpsPrefix):]
	if i := indexByte(host, '/'); i >= 0 {
		host = host[:i]
	}
	return &urlParts{Host: host}, nil
}

type urlParts struct{ Host string }

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
