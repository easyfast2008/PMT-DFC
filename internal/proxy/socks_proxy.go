// Package proxy hosts the local SOCKS5 listener that the user's browser
// (or any SOCKS5-aware app) connects to. Each incoming SOCKS5 connection
// is forwarded byte-for-byte over a fresh yamux stream — the SOCKS5
// handshake itself is parsed at the tunnel server, not locally.
//
// This keeps the local proxy stateless and small.
package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
)

// Server is the local SOCKS5 listener.
type Server struct {
	Listen string // e.g. "127.0.0.1:8085"
	Client *tunnel.Client
	Logger func(format string, args ...any)
}

// Run blocks until ctx is done.
func (s *Server) Run(ctx context.Context) error {
	if s.Logger == nil {
		s.Logger = func(string, ...any) {}
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", s.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	s.Logger("proxy: listening on %s", s.Listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.Logger("proxy: accept: %v", err)
			continue
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, local net.Conn) {
	defer local.Close()

	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	stream, err := s.Client.Open(dialCtx)
	if err != nil {
		s.Logger("proxy: open stream: %v", err)
		return
	}
	defer stream.Close()

	// Splice both directions. We do not parse the SOCKS5 frames here —
	// the server end of the stream parses them and dials the target.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(stream, local)
		_ = stream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(local, stream)
		if c, ok := local.(interface{ CloseWrite() error }); ok {
			_ = c.CloseWrite()
		} else {
			_ = local.Close()
		}
	}()
	wg.Wait()
}
