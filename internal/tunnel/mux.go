package tunnel

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Mux multiplexes multiple local SOCKS5 sessions into batched HTTP
// requests that are sent through a fronted relay to a VPS tunnel-node.
type Mux struct {
	authKey   string
	relayURL  string // full URL to the relay's batch endpoint
	client    *http.Client
	interval  time.Duration // batch send interval

	mu       sync.Mutex
	sessions map[string]*MuxSession
	stopped  bool
}

// MuxSession represents one tunneled TCP connection.
type MuxSession struct {
	ID         string
	Host       string
	Port       uint16
	localConn  net.Conn // the SOCKS5 client socket

	sendBuf    []byte
	sendMu     sync.Mutex

	recvCh     chan []byte // data from VPS → local
	connectErr chan error  // result of the initial connect op
	eof        bool
	closed     bool
	closeMu    sync.Mutex
}

// MuxConfig configures the batch multiplexer.
type MuxConfig struct {
	AuthKey      string
	RelayURL     string        // e.g. "https://script.google.com/macros/s/.../exec"
	HTTPClient   *http.Client  // pre-configured HTTP client (with fronted transport)
	BatchInterval time.Duration // how often to flush batches (default 100ms)
}

// NewMux creates a new batch multiplexer.
func NewMux(cfg MuxConfig) *Mux {
	interval := cfg.BatchInterval
	if interval == 0 {
		interval = 100 * time.Millisecond
	}
	return &Mux{
		authKey:  cfg.AuthKey,
		relayURL: cfg.RelayURL,
		client:   cfg.HTTPClient,
		interval: interval,
		sessions: make(map[string]*MuxSession),
	}
}

// NewSession creates a new tunneled session for the given target.
func (m *Mux) NewSession(localConn net.Conn, host string, port uint16) *MuxSession {
	var b [8]byte
	_, _ = rand.Read(b[:])
	sid := hex.EncodeToString(b[:])

	s := &MuxSession{
		ID:         sid,
		Host:       host,
		Port:       port,
		localConn:  localConn,
		recvCh:     make(chan []byte, 64),
		connectErr: make(chan error, 1),
	}
	m.mu.Lock()
	m.sessions[sid] = s
	m.mu.Unlock()
	return s
}

// RemoveSession removes a session from the mux.
func (m *Mux) RemoveSession(sid string) {
	m.mu.Lock()
	delete(m.sessions, sid)
	m.mu.Unlock()
}

// Run starts the batch send loop. Blocks until ctx is done.
func (m *Mux) Run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.mu.Lock()
			m.stopped = true
			m.mu.Unlock()
			return
		case <-ticker.C:
			m.sendBatch(ctx)
		}
	}
}

func (m *Mux) sendBatch(ctx context.Context) {
	m.mu.Lock()
	if len(m.sessions) == 0 {
		m.mu.Unlock()
		return
	}
	var ops []Op
	type opMeta struct {
		sid       string
		isConnect bool
	}
	var metas []opMeta

	for sid, s := range m.sessions {
		s.closeMu.Lock()
		closed := s.closed
		s.closeMu.Unlock()
		if closed {
			continue
		}

		s.sendMu.Lock()
		if s.Host != "" && s.Port != 0 {
			// Needs connect
			op := Op{Op: "connect", SID: sid, Host: s.Host, Port: s.Port}
			if len(s.sendBuf) > 0 {
				op.Data = EncodeData(s.sendBuf)
				s.sendBuf = nil
			}
			ops = append(ops, op)
			metas = append(metas, opMeta{sid: sid, isConnect: true})
			s.Host = "" // only send connect once
			s.Port = 0
		} else if len(s.sendBuf) > 0 || !s.eof {
			// Data or poll
			op := Op{Op: "data", SID: sid}
			if len(s.sendBuf) > 0 {
				op.Data = EncodeData(s.sendBuf)
				s.sendBuf = nil
			}
			ops = append(ops, op)
			metas = append(metas, opMeta{sid: sid, isConnect: false})
		}
		s.sendMu.Unlock()
	}
	m.mu.Unlock()

	if len(ops) == 0 {
		return
	}

	req := BatchRequest{Key: m.authKey, Ops: ops}
	body, err := json.Marshal(req)
	if err != nil {
		return
	}

	httpCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(httpCtx, http.MethodPost, m.relayURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := m.client.Do(httpReq)
	if err != nil {
		// Signal connect errors.
		for _, meta := range metas {
			if meta.isConnect {
				m.mu.Lock()
				s := m.sessions[meta.sid]
				m.mu.Unlock()
				if s != nil {
					select {
					case s.connectErr <- fmt.Errorf("relay: %w", err):
					default:
					}
				}
			}
		}
		return
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return
	}

	var batchResp BatchResponse
	if err := json.Unmarshal(respBody, &batchResp); err != nil {
		return
	}

	// Dispatch results.
	for i, result := range batchResp.Results {
		sid := result.SID
		if sid == "" && i < len(metas) {
			sid = metas[i].sid
		}
		m.mu.Lock()
		s, ok := m.sessions[sid]
		m.mu.Unlock()
		if !ok {
			continue
		}

		if i < len(metas) && metas[i].isConnect {
			if result.Err != "" {
				select {
				case s.connectErr <- fmt.Errorf("tunnel: %s", result.Err):
				default:
				}
				continue
			}
			select {
			case s.connectErr <- nil:
			default:
			}
		}

		if result.Data != "" {
			data, err := DecodeData(result.Data)
			if err == nil && len(data) > 0 {
				select {
				case s.recvCh <- data:
				default:
				}
			}
		}

		if result.EOF != nil && *result.EOF {
			s.closeMu.Lock()
			s.eof = true
			s.closed = true
			s.closeMu.Unlock()
			close(s.recvCh)
			m.RemoveSession(sid)
		}
	}
}

// QueueSend queues outbound data for a session.
func (s *MuxSession) QueueSend(data []byte) {
	s.sendMu.Lock()
	s.sendBuf = append(s.sendBuf, data...)
	s.sendMu.Unlock()
}

// WaitConnect blocks until the connect result is available.
func (s *MuxSession) WaitConnect(ctx context.Context) error {
	select {
	case err := <-s.connectErr:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ReadLoop reads data from VPS and writes to the local connection.
func (s *MuxSession) ReadLoop() {
	for data := range s.recvCh {
		if len(data) > 0 {
			_, err := s.localConn.Write(data)
			if err != nil {
				return
			}
		}
	}
}

// WriteLoop reads data from the local connection and queues it for sending.
func (s *MuxSession) WriteLoop() {
	buf := make([]byte, 32768)
	for {
		n, err := s.localConn.Read(buf)
		if n > 0 {
			cp := make([]byte, n)
			copy(cp, buf[:n])
			s.QueueSend(cp)
		}
		if err != nil {
			return
		}
	}
}

// Close marks the session as closed.
func (s *MuxSession) Close() {
	s.closeMu.Lock()
	s.closed = true
	s.closeMu.Unlock()
}
