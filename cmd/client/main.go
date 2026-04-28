// Command pmt-client is the local-side endpoint of the tunnel. It exposes
// a SOCKS5 listener that the user's browser (or any SOCKS5-aware app)
// connects to, then carries each connection over a fronted persistent
// HTTP/2 carrier to a Cloud Run pmt-server.
//
// Configuration is loaded from a JSON file (default: ./client.json) or
// from the path given by --config / PMT_CLIENT_CONFIG.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/easyfast2008/PMT-DFC/internal/auth"
	"github.com/easyfast2008/PMT-DFC/internal/dialer"
	"github.com/easyfast2008/PMT-DFC/internal/proxy"
	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
)

// Config is the on-disk client configuration.
type Config struct {
	// FrontDomain is the SNI value the firewall observes. e.g. "www.google.com".
	FrontDomain string `json:"front_domain"`
	// FrontIP is an optional fixed IP for the front domain. If empty, the
	// system resolver is used.
	FrontIP string `json:"front_ip"`
	// FrontPort defaults to 443.
	FrontPort int `json:"front_port"`
	// WorkerHost is the inner Host header — the actual Cloud Run hostname,
	// e.g. "pmt-tunnel-abc123-uc.a.run.app".
	WorkerHost string `json:"worker_host"`
	// TunnelPath defaults to "/tunnel".
	TunnelPath string `json:"tunnel_path"`
	// AuthKey is the PSK. Must match the server's PMT_AUTH_KEY (≥16 bytes).
	AuthKey string `json:"auth_key"`
	// Listen is the local SOCKS5 listen address. e.g. "127.0.0.1:8085".
	Listen string `json:"listen"`
	// LogLevel: debug|info|warn|error. Default info.
	LogLevel string `json:"log_level"`
	// InsecureSkipVerify disables certificate verification on the front TLS.
	// Only useful for local testing against a fake GFE. Never set in production.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

func main() {
	configPath := flag.String("config", lookupEnv("PMT_CLIENT_CONFIG", "client.json"), "path to client config JSON")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(2)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(cfg.LogLevel)}))
	slog.SetDefault(logger)

	d, err := dialer.New(dialer.Config{
		FrontDomain:        cfg.FrontDomain,
		FrontIP:            cfg.FrontIP,
		Port:               cfg.FrontPort,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
	if err != nil {
		logger.Error("dialer", "err", err)
		os.Exit(1)
	}

	tc, err := tunnel.NewClient(tunnel.ClientConfig{
		Dialer:     d,
		WorkerHost: cfg.WorkerHost,
		Path:       cfg.TunnelPath,
		Signer:     auth.NewSigner([]byte(cfg.AuthKey)),
		Logger:     func(format string, args ...any) { logger.Debug(fmt.Sprintf(format, args...)) },
	})
	if err != nil {
		logger.Error("tunnel client", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	go func() {
		if err := tc.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("tunnel client run", "err", err)
		}
	}()

	srv := &proxy.Server{
		Listen: cfg.Listen,
		Client: tc,
		Logger: func(format string, args ...any) { logger.Info(fmt.Sprintf(format, args...)) },
	}
	if err := srv.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("proxy run", "err", err)
		os.Exit(1)
	}
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.FrontDomain == "" {
		return nil, errors.New("front_domain is required")
	}
	if c.WorkerHost == "" {
		return nil, errors.New("worker_host is required")
	}
	if len(c.AuthKey) < 16 {
		return nil, errors.New("auth_key must be at least 16 bytes")
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8085"
	}
	if c.FrontPort == 0 {
		c.FrontPort = 443
	}
	if c.TunnelPath == "" {
		c.TunnelPath = "/tunnel"
	}
	return &c, nil
}

func parseLevel(s string) slog.Level {
	switch s {
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

func lookupEnv(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}
