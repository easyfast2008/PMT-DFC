package socks

import (
	"bytes"
	"io"
	"testing"
)

type rwBuf struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func (b *rwBuf) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b *rwBuf) Write(p []byte) (int, error) { return b.w.Write(p) }

func TestServeHandshakeDomain(t *testing.T) {
	in := bytes.Buffer{}
	// Greeting: VER=5, NMETHODS=1, METHODS=[0]
	in.Write([]byte{5, 1, 0})
	// Request: VER=5, CMD=CONNECT, RSV=0, ATYP=DOMAIN, LEN=11, "example.com", PORT=443
	in.Write([]byte{5, 1, 0, 3, 11})
	in.WriteString("example.com")
	in.Write([]byte{0x01, 0xbb})
	out := &bytes.Buffer{}
	rw := &rwBuf{r: &in, w: out}
	req, err := ServeHandshake(rw)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if req.Addr != "example.com:443" {
		t.Fatalf("addr=%q", req.Addr)
	}
	if got := out.Bytes(); len(got) < 2 || got[0] != 5 || got[1] != 0 {
		t.Fatalf("method reply = %v", got)
	}
}

func TestServeHandshakeIPv4(t *testing.T) {
	in := bytes.Buffer{}
	in.Write([]byte{5, 1, 0})
	in.Write([]byte{5, 1, 0, 1, 1, 2, 3, 4, 0x00, 0x50})
	out := &bytes.Buffer{}
	req, err := ServeHandshake(&rwBuf{r: &in, w: out})
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if req.Addr != "1.2.3.4:80" {
		t.Fatalf("addr=%q", req.Addr)
	}
}

func TestServeHandshakeRejectsBadVersion(t *testing.T) {
	in := bytes.Buffer{}
	in.Write([]byte{4, 1, 0})
	_, err := ServeHandshake(&rwBuf{r: &in, w: &bytes.Buffer{}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestServeHandshakeRejectsTruncated(t *testing.T) {
	in := bytes.Buffer{}
	in.Write([]byte{5, 1})
	_, err := ServeHandshake(&rwBuf{r: &in, w: &bytes.Buffer{}})
	if err == nil || err == io.EOF {
		t.Fatalf("expected wrapped error, got %v", err)
	}
}

func TestWriteReply(t *testing.T) {
	out := &bytes.Buffer{}
	if err := WriteReply(out, ReplySuccess); err != nil {
		t.Fatal(err)
	}
	if got := out.Bytes(); len(got) != 10 || got[0] != 5 || got[1] != 0 {
		t.Fatalf("bad reply %v", got)
	}
}
