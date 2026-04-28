package tunnel

import (
	"net"
	"testing"
	"time"
)

func TestSessionManager_ConnectDataClose(t *testing.T) {
	// Start a TCP echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	_, port, _ := net.SplitHostPort(ln.Addr().String())

	sm := NewSessionManager(10 * time.Second)
	sid := "test-session-1"

	// Connect.
	result := sm.ProcessBatch([]Op{
		{Op: "connect", SID: sid, Host: "127.0.0.1", Port: mustPort(port)},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].Err != "" {
		t.Fatalf("connect error: %s", result[0].Err)
	}
	if result[0].SID != sid {
		t.Fatalf("expected SID %q, got %q", sid, result[0].SID)
	}

	// Send data.
	payload := EncodeData([]byte("hello"))
	result = sm.ProcessBatch([]Op{
		{Op: "data", SID: sid, Data: payload},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].Err != "" {
		t.Fatalf("data error: %s", result[0].Err)
	}

	// Wait for echo response.
	time.Sleep(200 * time.Millisecond)
	result = sm.ProcessBatch([]Op{
		{Op: "data", SID: sid},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	data, err := DecodeData(result[0].Data)
	if err != nil {
		t.Fatalf("decode data: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("expected echo 'hello', got %q", string(data))
	}

	// Close.
	result = sm.ProcessBatch([]Op{
		{Op: "close", SID: sid},
	})
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].EOF == nil || !*result[0].EOF {
		t.Fatal("expected EOF on close")
	}

	if sm.Count() != 0 {
		t.Fatalf("expected 0 sessions, got %d", sm.Count())
	}
}

func TestSessionManager_ConnectBadHost(t *testing.T) {
	sm := NewSessionManager(10 * time.Second)
	result := sm.ProcessBatch([]Op{
		{Op: "connect", SID: "bad-1", Host: "192.0.2.1", Port: 1},
	})
	if len(result) != 1 {
		t.Fatal("expected 1 result")
	}
	if result[0].Err == "" {
		t.Fatal("expected error for unreachable host")
	}
}

func mustPort(s string) uint16 {
	var p uint16
	for _, c := range s {
		p = p*10 + uint16(c-'0')
	}
	return p
}
