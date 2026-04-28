package auth

import (
	"strings"
	"testing"
	"time"
)

func TestSignAndVerifyRoundTrip(t *testing.T) {
	psk := []byte("super-secret-key-for-tests-only-32b")
	s := NewSigner(psk)
	v := NewVerifier(psk, 1024)

	tok, err := s.Token()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !strings.HasPrefix(tok, Scheme+" ") {
		t.Fatalf("unexpected scheme prefix: %q", tok)
	}
	if err := v.Verify(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestReplayRejected(t *testing.T) {
	psk := []byte("k")
	s := NewSigner(psk)
	v := NewVerifier(psk, 16)
	tok, _ := s.Token()
	if err := v.Verify(tok); err != nil {
		t.Fatalf("first verify: %v", err)
	}
	if err := v.Verify(tok); err == nil {
		t.Fatalf("replay was accepted")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	s := NewSigner([]byte("k1"))
	v := NewVerifier([]byte("k2"), 16)
	tok, _ := s.Token()
	if err := v.Verify(tok); err == nil {
		t.Fatalf("wrong key accepted")
	}
}

func TestSkewRejected(t *testing.T) {
	psk := []byte("k")
	s := NewSigner(psk)
	v := NewVerifier(psk, 16)
	old := MaxSkew
	defer func() { MaxSkew = old }()
	MaxSkew = 1 * time.Millisecond
	tok, _ := s.Token()
	time.Sleep(20 * time.Millisecond)
	if err := v.Verify(tok); err == nil {
		t.Fatalf("stale token accepted")
	}
}

func TestGarbageRejected(t *testing.T) {
	v := NewVerifier([]byte("k"), 16)
	for _, bad := range []string{"", "PMT", "PMT ", "PMT not-base64!!!", "Bearer abc"} {
		if err := v.Verify(bad); err == nil {
			t.Fatalf("garbage accepted: %q", bad)
		}
	}
}

func TestCacheEviction(t *testing.T) {
	psk := []byte("k")
	s := NewSigner(psk)
	v := NewVerifier(psk, 4)
	for i := 0; i < 10; i++ {
		tok, err := s.Token()
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Verify(tok); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if got := len(v.seen); got > 4 {
		t.Fatalf("cache exceeded bound: %d", got)
	}
}
