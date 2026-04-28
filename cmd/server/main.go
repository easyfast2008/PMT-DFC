// Command pmt-server is the VPS tunnel-node.
//
// It accepts batch JSON requests at POST /tunnel/batch, manages persistent
// TCP sessions to upstream targets, and returns responses. Designed to sit
// behind a relay (Apps Script or Cloudflare Worker) that forwards fronted
// requests from censored clients.
//
// Protocol is wire-compatible with MhR's tunnel-node batch format.
//
// Env:
//
//	PORT             listen port (default 8080)
//	PMT_AUTH_KEY     shared secret (required, min 16 bytes)
package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
)

func main() {
	level := slog.LevelInfo
	if os.Getenv("PMT_LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	authKey := os.Getenv("PMT_AUTH_KEY")
	if len(authKey) < 16 {
		log.Error("PMT_AUTH_KEY must be at least 16 characters")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	sm := tunnel.NewSessionManager(120 * time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("POST /tunnel/batch", batchHandler(log, authKey, sm))
	// Legacy single-op endpoint for compatibility.
	mux.HandleFunc("POST /tunnel", batchHandler(log, authKey, sm))

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Session reaper.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := sm.ReapIdle(); n > 0 {
					log.Info("reaped idle sessions", "count", n)
				}
				log.Debug("sessions", "active", sm.Count())
			}
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Info("pmt-server listening", "port", port, "sessions_idle_timeout", "120s")
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Error("server error", "err", err)
		os.Exit(1)
	}
}

func batchHandler(log *slog.Logger, authKey string, sm *tunnel.SessionManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		defer r.Body.Close()

		var req tunnel.BatchRequest
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}

		if req.Key != authKey {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		log.Debug("batch", "ops", len(req.Ops))
		results := sm.ProcessBatch(req.Ops)

		// Collect SIDs that had data ops for drain phase.
		var dataSIDs []string
		hasWrites := false
		for _, op := range req.Ops {
			if op.Op == "data" || op.Op == "connect" {
				dataSIDs = append(dataSIDs, op.SID)
				if op.Data != "" {
					hasWrites = true
				}
			}
		}

		// If there were writes, give upstream servers time to respond.
		if hasWrites && len(dataSIDs) > 0 {
			extra := sm.DrainAll(dataSIDs, 200*time.Millisecond)
			for i, result := range results {
				if data, ok := extra[result.SID]; ok && len(data) > 0 {
					existing, _ := tunnel.DecodeData(results[i].Data)
					existing = append(existing, data...)
					results[i].Data = tunnel.EncodeData(existing)
				}
			}
		}

		resp := tunnel.BatchResponse{Results: results}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}
