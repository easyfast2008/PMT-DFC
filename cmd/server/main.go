// Command pmt-server is the Cloud Run-side endpoint of the tunnel.
//
// It accepts HTTP/2 streaming POST requests on /tunnel, authenticates
// them, multiplexes the body using yamux, and treats each accepted yamux
// stream as a SOCKS5 inner connection that it dials out from the Cloud Run
// container.
//
// Flags / env:
//
//	PORT          (Cloud Run-provided) listen port. Default 8080.
//	PMT_AUTH_KEY  (required) PSK shared with clients. Min 16 bytes.
//	PMT_LOG_LEVEL info|debug. Default info.
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/auth"
	"github.com/easyfast2008/PMT-DFC/internal/exit"
	"github.com/easyfast2008/PMT-DFC/internal/socks"
	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
	"github.com/hashicorp/yamux"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: levelFromEnv(),
	}))
	slog.SetDefault(logger)

	psk := os.Getenv("PMT_AUTH_KEY")
	if len(psk) < 16 {
		logger.Error("PMT_AUTH_KEY must be set and at least 16 bytes")
		os.Exit(2)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	verifier := auth.NewVerifier([]byte(psk), 200_000)
	dialer := exit.NewDirect()

	streamHandler := func(stream *yamux.Stream) {
		handleStream(context.Background(), stream, dialer, logger)
	}

	mux := http.NewServeMux()
	mux.Handle("/tunnel", tunnel.ServerHandler(verifier, streamHandler))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	})

	h2s := &http2.Server{
		MaxConcurrentStreams: 1024,
		IdleTimeout:          0, // we keep the carrier open ourselves
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           h2c.NewHandler(mux, h2s),
		ReadHeaderTimeout: 10 * time.Second,
		// Read/Write timeouts MUST be 0 — the tunnel is long-lived.
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shCtx)
	}()

	logger.Info("pmt-server listening", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server failed", "err", err)
		os.Exit(1)
	}
}

func levelFromEnv() slog.Level {
	switch os.Getenv("PMT_LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func handleStream(ctx context.Context, stream *yamux.Stream, dialer exit.Dialer, log *slog.Logger) {
	defer stream.Close()
	req, err := socks.ServeHandshake(stream)
	if err != nil {
		log.Debug("socks handshake failed", "err", err)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	target, err := dialer.DialContext(dialCtx, req.Addr)
	if err != nil {
		_ = socks.WriteReply(stream, socks.CodeFromError(err))
		log.Debug("egress dial failed", "addr", req.Addr, "err", err)
		return
	}
	if err := socks.WriteReply(stream, socks.ReplySuccess); err != nil {
		_ = target.Close()
		return
	}
	splice(stream, target)
}

func splice(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		halfClose(a)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		halfClose(b)
	}()
	wg.Wait()
	_ = a.Close()
	_ = b.Close()
}

func halfClose(c net.Conn) {
	type cw interface{ CloseWrite() error }
	if x, ok := c.(cw); ok {
		_ = x.CloseWrite()
	}
}
