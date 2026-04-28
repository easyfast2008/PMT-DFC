// Package socks implements the minimum of SOCKS5 (RFC 1928) needed by the
// tunnel.
//
// Why SOCKS5?
//
//   - It is protocol-agnostic at the inner layer (any TCP).
//   - With the DOMAIN address type, the client never resolves DNS itself —
//     the exit resolves it. This is how we avoid client DNS leaks without
//     building a separate DNS-over-tunnel channel for typical browser usage.
//
// Authentication is not used at this layer — the carrier is already
// authenticated by package internal/auth, and the inner streams cannot reach
// the network without first traversing the carrier.
package socks

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

const (
	verSocks5 = 0x05

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	authNone = 0x00
)

// Reply codes (RFC 1928 §6).
const (
	ReplySuccess         = 0x00
	ReplyGeneralFailure  = 0x01
	ReplyConnNotAllowed  = 0x02 //nolint:unused,deadcode
	ReplyNetUnreachable  = 0x03
	ReplyHostUnreachable = 0x04
	ReplyConnRefused     = 0x05
	ReplyTTLExpired      = 0x06 //nolint:unused,deadcode
	ReplyCmdNotSupported = 0x07
	ReplyAtypNotSupp     = 0x08 //nolint:unused,deadcode
)

// Request describes a parsed CONNECT request.
type Request struct {
	Addr string // "host:port" — host may be a domain or an IP literal
	Port uint16
}

// ServeHandshake reads the SOCKS5 greeting and CONNECT request from rw.
//
// On success it returns the parsed Request. The caller is then responsible
// for dialing Req.Addr and calling WriteReply.
//
// Only the CONNECT command and "no authentication" are supported.
func ServeHandshake(rw io.ReadWriter) (*Request, error) {
	// Greeting: VER, NMETHODS, METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(rw, hdr); err != nil {
		return nil, fmt.Errorf("socks: read greeting: %w", err)
	}
	if hdr[0] != verSocks5 {
		return nil, fmt.Errorf("socks: unsupported version %d", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(rw, methods); err != nil {
		return nil, fmt.Errorf("socks: read methods: %w", err)
	}
	if _, err := rw.Write([]byte{verSocks5, authNone}); err != nil {
		return nil, fmt.Errorf("socks: write method: %w", err)
	}

	// Request: VER, CMD, RSV, ATYP, ADDR, PORT
	rh := make([]byte, 4)
	if _, err := io.ReadFull(rw, rh); err != nil {
		return nil, fmt.Errorf("socks: read req header: %w", err)
	}
	if rh[0] != verSocks5 {
		return nil, fmt.Errorf("socks: req unexpected version %d", rh[0])
	}
	if rh[1] != cmdConnect {
		return nil, fmt.Errorf("socks: cmd %d not supported", rh[1])
	}
	var host string
	switch rh[3] {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(rw, ip); err != nil {
			return nil, fmt.Errorf("socks: read ipv4: %w", err)
		}
		host = net.IP(ip).String()
	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(rw, ip); err != nil {
			return nil, fmt.Errorf("socks: read ipv6: %w", err)
		}
		host = net.IP(ip).String()
	case atypDomain:
		l := make([]byte, 1)
		if _, err := io.ReadFull(rw, l); err != nil {
			return nil, fmt.Errorf("socks: read dlen: %w", err)
		}
		dom := make([]byte, l[0])
		if _, err := io.ReadFull(rw, dom); err != nil {
			return nil, fmt.Errorf("socks: read domain: %w", err)
		}
		host = string(dom)
	default:
		return nil, fmt.Errorf("socks: atyp %d not supported", rh[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(rw, pb); err != nil {
		return nil, fmt.Errorf("socks: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(pb)
	if host == "" || port == 0 {
		return nil, errors.New("socks: empty host or zero port")
	}
	return &Request{Addr: net.JoinHostPort(host, strconv.Itoa(int(port))), Port: port}, nil
}

// WriteReply writes a SOCKS5 reply with the given code. The bound address is
// reported as 0.0.0.0:0 — clients have no use for it and reporting the real
// exit address would leak Cloud Run egress IPs.
func WriteReply(w io.Writer, code byte) error {
	// VER, REP, RSV, ATYP=ipv4, BND.ADDR=0.0.0.0, BND.PORT=0
	resp := []byte{verSocks5, code, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := w.Write(resp)
	return err
}

// CodeFromError maps a Go net error to a SOCKS5 reply code.
func CodeFromError(err error) byte {
	if err == nil {
		return ReplySuccess
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Err != nil {
			s := ne.Err.Error()
			switch {
			case contains(s, "connection refused"):
				return ReplyConnRefused
			case contains(s, "network is unreachable"):
				return ReplyNetUnreachable
			case contains(s, "no such host"), contains(s, "host is down"):
				return ReplyHostUnreachable
			}
		}
	}
	return ReplyGeneralFailure
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
