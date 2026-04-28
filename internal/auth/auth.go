// Package auth implements pre-shared-key authentication for the tunnel
// carrier with replay protection.
//
// The client computes:
//
//	token = base64( timestamp || nonce || HMAC-SHA256(key, timestamp || nonce) )
//
// and sends it in the Authorization header as `PMT <token>`.
//
// The server verifies:
//  1. The HMAC matches.
//  2. The timestamp is within the allowed clock skew window.
//  3. The nonce has not been seen recently (LRU cache).
//
// This is a deliberate, minimal scheme. It is sufficient to keep the tunnel
// closed to anyone who does not hold the PSK, while leaving room for future
// migration to mTLS or signed JWTs without changing the carrier protocol.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Header is the HTTP header carrying the auth token.
const Header = "Authorization"

// Scheme is the prefix expected in the Authorization header.
const Scheme = "PMT"

const (
	tsLen    = 8  // int64 unix nanoseconds
	nonceLen = 16 // 128-bit random nonce
	macLen   = 32 // sha256
	tokenLen = tsLen + nonceLen + macLen
)

// MaxSkew is how far a client clock may drift from the server.
//
// Cloud Run instances run NTP-synced; clients in firewalled environments may
// have less reliable clocks. 60 s is a reasonable balance between resistance
// to long-window replay and tolerance of bad clocks.
var MaxSkew = 60 * time.Second

// ErrInvalid is returned when a token fails verification for any reason.
var ErrInvalid = errors.New("auth: invalid token")

// Signer creates auth tokens.
type Signer struct {
	key []byte
}

// NewSigner returns a Signer that uses the given PSK.
func NewSigner(psk []byte) *Signer {
	return &Signer{key: append([]byte(nil), psk...)}
}

// Token returns a fresh auth token. Callers MUST send each token at most once
// per server (the server refuses replays via its nonce cache).
func (s *Signer) Token() (string, error) {
	buf := make([]byte, tokenLen)
	binary.BigEndian.PutUint64(buf[:tsLen], uint64(time.Now().UnixNano()))
	if _, err := rand.Read(buf[tsLen : tsLen+nonceLen]); err != nil {
		return "", fmt.Errorf("auth: rng: %w", err)
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write(buf[:tsLen+nonceLen])
	copy(buf[tsLen+nonceLen:], mac.Sum(nil))
	return Scheme + " " + base64.RawURLEncoding.EncodeToString(buf), nil
}

// Verifier validates auth tokens.
//
// It maintains a bounded LRU of recently seen nonces to refuse replays inside
// the clock-skew window. The cache is bounded to keep memory usage predictable
// under attack; once full, the oldest entries are evicted.
type Verifier struct {
	key []byte

	mu     sync.Mutex
	seen   map[string]time.Time
	maxLen int
}

// NewVerifier returns a Verifier. cacheSize bounds the nonce LRU; values
// around 100k–1M are reasonable for a single Cloud Run instance.
func NewVerifier(psk []byte, cacheSize int) *Verifier {
	if cacheSize <= 0 {
		cacheSize = 100_000
	}
	return &Verifier{
		key:    append([]byte(nil), psk...),
		seen:   make(map[string]time.Time, cacheSize),
		maxLen: cacheSize,
	}
}

// Verify parses an Authorization header value and returns nil on success.
func (v *Verifier) Verify(headerValue string) error {
	if len(headerValue) <= len(Scheme)+1 || headerValue[:len(Scheme)] != Scheme {
		return ErrInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(headerValue[len(Scheme)+1:])
	if err != nil || len(raw) != tokenLen {
		return ErrInvalid
	}
	expectedMac := hmac.New(sha256.New, v.key)
	expectedMac.Write(raw[:tsLen+nonceLen])
	if !hmac.Equal(expectedMac.Sum(nil), raw[tsLen+nonceLen:]) {
		return ErrInvalid
	}
	tsNano := int64(binary.BigEndian.Uint64(raw[:tsLen]))
	ts := time.Unix(0, tsNano)
	now := time.Now()
	skew := now.Sub(ts)
	if skew < 0 {
		skew = -skew
	}
	if skew > MaxSkew {
		return ErrInvalid
	}
	nonce := string(raw[tsLen : tsLen+nonceLen])
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, dup := v.seen[nonce]; dup {
		return ErrInvalid
	}
	if len(v.seen) >= v.maxLen {
		// Evict expired entries first; if none, drop one arbitrary entry.
		cutoff := now.Add(-MaxSkew)
		for n, t := range v.seen {
			if t.Before(cutoff) {
				delete(v.seen, n)
			}
		}
		if len(v.seen) >= v.maxLen {
			for n := range v.seen {
				delete(v.seen, n)
				break
			}
		}
	}
	v.seen[nonce] = now
	return nil
}
