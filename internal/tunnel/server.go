// Package tunnel wires the carrier (HTTP/2 streaming POST) and the stream
// multiplexer (yamux) together for both client and server.
//
// Reconnect semantics
//
// When a carrier breaks (e.g. GFE drops an idle h2 stream after ~5 min, or a
// Cloud Run instance is rolled), the client transparently redials. However,
// any yamux streams that were in flight at the moment of the break are NOT
// resumed — they return io.EOF to their callers. This is by design:
//
//   - Yamux state (window credits, in-flight stream IDs) is not migratable
//     across carriers without protocol-level resumption support.
//   - SOCKS5 / raw TCP have no resumption protocol; the only correct
//     behavior on an unrecoverable mid-stream break is to surface the error
//     to the application and let it decide what to do (retry idempotent
//     GETs, fail uploads, etc.).
//
// In practice this is identical to a real TCP connection being reset, which
// every networked application already handles. We do NOT pretend it is
// transparent.
package tunnel

import (
	"errors"
	"io"
	"net/http"

	"github.com/easyfast2008/PMT-DFC/internal/auth"
	"github.com/hashicorp/yamux"
)

// ServerHandler returns an http.Handler that accepts streaming-POST tunnel
// requests, authenticates them, and serves a yamux session whose accepted
// streams are passed to streamHandler.
//
// streamHandler runs in its own goroutine per stream. It must Close the
// stream when done.
func ServerHandler(verifier *auth.Verifier, streamHandler func(*yamux.Stream)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ProtoMajor != 2 {
			http.Error(w, "http/2 required", http.StatusUpgradeRequired)
			return
		}
		if err := verifier.Verify(r.Header.Get(auth.Header)); err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		// Send a single byte and flush so the client sees its read side become
		// readable immediately. This catches misbehaving intermediaries that
		// would otherwise buffer the entire response.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		conn := &duplexHTTP2{
			r:       r.Body,
			w:       w,
			flusher: flusher,
		}
		cfg := yamux.DefaultConfig()
		cfg.LogOutput = io.Discard
		session, err := yamux.Server(conn, cfg)
		if err != nil {
			return
		}
		defer session.Close()

		for {
			stream, err := session.AcceptStream()
			if err != nil {
				if errors.Is(err, yamux.ErrSessionShutdown) {
					return
				}
				return
			}
			go streamHandler(stream)
		}
	})
}
