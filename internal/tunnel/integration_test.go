package tunnel_test

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/auth"
	"github.com/easyfast2008/PMT-DFC/internal/exit"
	"github.com/easyfast2008/PMT-DFC/internal/socks"
	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
	"github.com/hashicorp/yamux"
)

// Test_EndToEnd boots a real h2c tunnel server backed by an in-process
// echo target, then drives it through the same HTTP/2 client transport
// the production tunnel client uses. It verifies:
//
//   - PSK auth gates access (wrong key → 401, no key → 401).
//   - A successful POST yields a streaming body suitable for yamux.
//   - SOCKS5 CONNECT inside a yamux stream reaches the egress dialer.
//   - Bytes flow bidirectionally through the full splice.
func Test_EndToEnd(t *testing.T) {
	psk := []byte("test-psk-must-be-16+bytes-long")
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
			t.Logf("handshake: %v", err)
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
		spliceForTest(stream, target)
	}

	mux := http.NewServeMux()
	mux.Handle("/tunnel", tunnel.ServerHandler(verifier, streamHandler))
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)

	t.Run("missing auth", func(t *testing.T) {
		resp, err := srv.Client().Post(srv.URL+"/tunnel", "application/octet-stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		bad := auth.NewSigner([]byte("wrong-key-but-still-16-bytes--"))
		tok, _ := bad.Token()
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/tunnel", nil)
		req.Header.Set(auth.Header, tok)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", resp.StatusCode)
		}
	})

	t.Run("happy path", func(t *testing.T) {
		signer := auth.NewSigner(psk)
		// Build the carrier: streaming POST with a yamux client on top.
		pr, pw := io.Pipe()
		req, err := http.NewRequest(http.MethodPost, srv.URL+"/tunnel", pr)
		if err != nil {
			t.Fatal(err)
		}
		tok, _ := signer.Token()
		req.Header.Set(auth.Header, tok)
		req.Header.Set("Content-Type", "application/octet-stream")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		req = req.WithContext(ctx)

		client := srv.Client()
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}

		conn := &readWriteCloser{r: resp.Body, w: pw}
		ycfg := yamux.DefaultConfig()
		ycfg.LogOutput = io.Discard
		sess, err := yamux.Client(conn, ycfg)
		if err != nil {
			t.Fatal(err)
		}
		defer sess.Close()

		stream, err := sess.OpenStream()
		if err != nil {
			t.Fatal(err)
		}
		defer stream.Close()

		// Greeting: VER=5, NMETHODS=1, METHODS=[0]
		if _, err := stream.Write([]byte{5, 1, 0}); err != nil {
			t.Fatal(err)
		}
		method := make([]byte, 2)
		if _, err := io.ReadFull(stream, method); err != nil {
			t.Fatal(err)
		}
		if method[0] != 5 || method[1] != 0 {
			t.Fatalf("bad method response %v", method)
		}

		host, port, _ := net.SplitHostPort(echoListener.Addr().String())
		var portNum uint16
		_, _ = parseUint16(port, &portNum)
		req5 := []byte{5, 1, 0, 3, byte(len(host))}
		req5 = append(req5, []byte(host)...)
		req5 = binary.BigEndian.AppendUint16(req5, portNum)
		if _, err := stream.Write(req5); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(stream, reply); err != nil {
			t.Fatal(err)
		}
		if reply[0] != 5 || reply[1] != 0 {
			t.Fatalf("bad reply %v", reply)
		}

		payload := []byte("hello from tunnel")
		if _, err := stream.Write(payload); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(stream, got); err != nil {
			t.Fatalf("echo read: %v", err)
		}
		if string(got) != string(payload) {
			t.Fatalf("echo mismatch: got %q", got)
		}
	})
}

func runEcho(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}(c)
	}
}

func spliceForTest(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(a, b); _ = a.Close() }()
	go func() { defer wg.Done(); _, _ = io.Copy(b, a); _ = b.Close() }()
	wg.Wait()
}

type readWriteCloser struct {
	r io.ReadCloser
	w io.WriteCloser
}

func (rw *readWriteCloser) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *readWriteCloser) Write(p []byte) (int, error) { return rw.w.Write(p) }
func (rw *readWriteCloser) Close() error {
	_ = rw.w.Close()
	return rw.r.Close()
}

func parseUint16(s string, dst *uint16) (int, error) {
	var n uint32
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return i, nil
		}
		n = n*10 + uint32(c-'0')
	}
	*dst = uint16(n)
	return len(s), nil
}
