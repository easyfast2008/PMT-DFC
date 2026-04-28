// Command pmt-client is the local proxy that tunnels SOCKS5 connections
// through a fronted relay (Google Apps Script or Cloudflare Worker) to
// a VPS tunnel-node.
//
// Configuration is loaded from a JSON file (default: ./client.json).
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/easyfast2008/PMT-DFC/internal/dialer"
	"github.com/easyfast2008/PMT-DFC/internal/socks"
	"github.com/easyfast2008/PMT-DFC/internal/tunnel"
)

// Config is the on-disk client configuration.
type Config struct {
	// Listen address for the local SOCKS5 proxy (default "127.0.0.1:8085").
	Listen string `json:"listen"`

	// Relay is the type of relay: "apps_script" or "cloudflare_worker".
	Relay string `json:"relay"`

	// ScriptID is the Apps Script deployment ID (for relay=apps_script).
	ScriptID string `json:"script_id"`

	// ScriptIDs allows multiple Apps Script deployments for pipelining.
	ScriptIDs []string `json:"script_ids"`

	// WorkerURL is the Cloudflare Worker URL (for relay=cloudflare_worker).
	WorkerURL string `json:"worker_url"`

	// AuthKey is the shared secret between client and VPS tunnel-node.
	AuthKey string `json:"auth_key"`

	// FrontDomain is the SNI value the firewall observes (default "www.google.com").
	FrontDomain string `json:"front_domain"`

	// FrontIP is a fixed Google IP to use (skips DNS).
	FrontIP string `json:"front_ip"`

	// BatchInterval is how often batches are sent in milliseconds (default 100).
	BatchInterval int `json:"batch_interval_ms"`
}

func main() {
	cfgPath := flag.String("config", "client.json", "path to client config")
	flag.Parse()

	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	data, err := os.ReadFile(*cfgPath)
	if err != nil {
		log.Error("read config", "path", *cfgPath, "err", err)
		os.Exit(1)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		log.Error("parse config", "err", err)
		os.Exit(1)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8085"
	}
	if cfg.FrontDomain == "" {
		cfg.FrontDomain = "www.google.com"
	}
	if cfg.AuthKey == "" {
		log.Error("auth_key is required")
		os.Exit(1)
	}

	// Build relay URL based on relay type.
	relayURL, relayHost := buildRelayURL(&cfg)
	if relayURL == "" {
		log.Error("could not build relay URL — check relay type and script_id/worker_url")
		os.Exit(1)
	}
	log.Info("relay", "type", cfg.Relay, "url", relayURL)

	// Build fronted HTTP client.
	httpClient := buildHTTPClient(&cfg, relayHost)

	interval := time.Duration(cfg.BatchInterval) * time.Millisecond
	if interval == 0 {
		interval = 100 * time.Millisecond
	}

	mux := tunnel.NewMux(tunnel.MuxConfig{
		AuthKey:       cfg.AuthKey,
		RelayURL:      relayURL,
		HTTPClient:    httpClient,
		BatchInterval: interval,
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go mux.Run(ctx)

	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	defer ln.Close()
	log.Info("SOCKS5 listening", "addr", cfg.Listen)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn("accept", "err", err)
			continue
		}
		go handleSOCKS(ctx, log, mux, conn)
	}
}

func handleSOCKS(ctx context.Context, log *slog.Logger, mux *tunnel.Mux, conn net.Conn) {
	defer conn.Close()

	req, err := socks.ServeHandshake(conn)
	if err != nil {
		log.Debug("socks handshake", "err", err)
		return
	}

	host, portStr, err := net.SplitHostPort(req.Addr)
	if err != nil {
		_ = socks.WriteReply(conn, socks.ReplyGeneralFailure)
		return
	}
	port64, _ := strconv.ParseUint(portStr, 10, 16)
	port := uint16(port64)

	log.Debug("connect", "target", req.Addr)

	sess := mux.NewSession(conn, host, port)
	defer func() {
		sess.Close()
		mux.RemoveSession(sess.ID)
	}()

	// Wait for connect result from VPS.
	connectCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := sess.WaitConnect(connectCtx); err != nil {
		log.Debug("connect failed", "target", req.Addr, "err", err)
		_ = socks.WriteReply(conn, socks.ReplyHostUnreachable)
		return
	}

	_ = socks.WriteReply(conn, socks.ReplySuccess)

	// Splice data bidirectionally.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sess.ReadLoop()
	}()
	go func() {
		defer wg.Done()
		sess.WriteLoop()
	}()
	wg.Wait()
}

func buildRelayURL(cfg *Config) (string, string) {
	switch cfg.Relay {
	case "apps_script", "":
		id := cfg.ScriptID
		if id == "" && len(cfg.ScriptIDs) > 0 {
			id = cfg.ScriptIDs[0]
		}
		if id == "" {
			return "", ""
		}
		url := fmt.Sprintf("https://script.google.com/macros/s/%s/exec", id)
		return url, "script.google.com"
	case "cloudflare_worker":
		if cfg.WorkerURL == "" {
			return "", ""
		}
		u := cfg.WorkerURL
		if !strings.HasSuffix(u, "/tunnel/batch") {
			u = strings.TrimRight(u, "/") + "/tunnel/batch"
		}
		// Extract host from URL.
		host := cfg.WorkerURL
		host = strings.TrimPrefix(host, "https://")
		host = strings.TrimPrefix(host, "http://")
		if idx := strings.Index(host, "/"); idx >= 0 {
			host = host[:idx]
		}
		return u, host
	default:
		return "", ""
	}
}

func buildHTTPClient(cfg *Config, relayHost string) *http.Client {
	d, err := dialer.New(dialer.Config{
		FrontDomain: cfg.FrontDomain,
		FrontIP:     cfg.FrontIP,
		Port:        443,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dialer: %v\n", err)
		os.Exit(1)
	}

	transport := &http.Transport{
		// Override TLS dialing to use our fronted dialer.
		// The TLS handshake uses SNI=FrontDomain; HTTP Host header
		// is set from the request URL (relayHost).
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx)
		},
		// Increase pool size for pipelining.
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 30,
		IdleConnTimeout:     45 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: false},
	}
	return &http.Client{Transport: transport, Timeout: 35 * time.Second}
}
