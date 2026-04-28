package tunnel

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// SessionManager manages TCP sessions for the VPS tunnel-node.
// Each session is a persistent TCP connection to a target host.
type SessionManager struct {
	mu       sync.Mutex
	sessions map[string]*session
	idleMax  time.Duration
}

type session struct {
	conn       net.Conn
	readBuf    []byte
	eof        bool
	lastActive time.Time
	mu         sync.Mutex
	readDone   chan struct{} // closed when background reader exits
}

// NewSessionManager creates a session manager with the given idle timeout.
func NewSessionManager(idleTimeout time.Duration) *SessionManager {
	if idleTimeout == 0 {
		idleTimeout = 120 * time.Second
	}
	return &SessionManager{
		sessions: make(map[string]*session),
		idleMax:  idleTimeout,
	}
}

// ProcessBatch handles a batch of operations and returns results.
func (m *SessionManager) ProcessBatch(ops []Op) []OpResult {
	results := make([]OpResult, len(ops))
	for i, op := range ops {
		switch op.Op {
		case "connect":
			results[i] = m.opConnect(op)
		case "data":
			results[i] = m.opData(op)
		case "close":
			results[i] = m.opClose(op)
		default:
			results[i] = OpResult{SID: op.SID, Err: "unsupported op: " + op.Op}
		}
	}
	return results
}

// DrainAll reads available data from all active sessions after processing
// writes. Called after ProcessBatch to collect any server-push data that
// arrived while we were writing.
func (m *SessionManager) DrainAll(sids []string, timeout time.Duration) map[string][]byte {
	if timeout == 0 {
		timeout = 350 * time.Millisecond
	}
	time.Sleep(timeout)

	out := make(map[string][]byte)
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, sid := range sids {
		s, ok := m.sessions[sid]
		if !ok {
			continue
		}
		s.mu.Lock()
		if len(s.readBuf) > 0 {
			out[sid] = s.readBuf
			s.readBuf = nil
		}
		s.mu.Unlock()
	}
	return out
}

func (m *SessionManager) opConnect(op Op) OpResult {
	sid := op.SID
	if sid == "" {
		return OpResult{Err: "connect: missing sid"}
	}
	if op.Host == "" || op.Port == 0 {
		return OpResult{SID: sid, Err: "connect: missing host or port"}
	}

	addr := net.JoinHostPort(op.Host, fmt.Sprintf("%d", op.Port))
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return OpResult{SID: sid, Err: fmt.Sprintf("connect: %v", err)}
	}
	_ = conn.(*net.TCPConn).SetNoDelay(true)

	s := &session{
		conn:       conn,
		lastActive: time.Now(),
		readDone:   make(chan struct{}),
	}
	go m.readerLoop(sid, s)

	// If client sent initial data with the connect op, write it now.
	if op.Data != "" {
		payload, err := DecodeData(op.Data)
		if err != nil {
			return OpResult{SID: sid, Err: "connect: bad base64"}
		}
		if len(payload) > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, _ = conn.Write(payload)
			_ = conn.SetWriteDeadline(time.Time{})
		}
	}

	m.mu.Lock()
	m.sessions[sid] = s
	m.mu.Unlock()

	// Brief wait for initial response (e.g., TLS ServerHello).
	time.Sleep(100 * time.Millisecond)
	s.mu.Lock()
	data := s.readBuf
	s.readBuf = nil
	eof := s.eof
	s.mu.Unlock()

	r := OpResult{SID: sid, Data: EncodeData(data)}
	if eof {
		r.EOF = boolPtr(true)
	}
	return r
}

func (m *SessionManager) opData(op Op) OpResult {
	sid := op.SID
	m.mu.Lock()
	s, ok := m.sessions[sid]
	m.mu.Unlock()
	if !ok {
		return OpResult{SID: sid, Err: "data: unknown session"}
	}

	s.mu.Lock()
	s.lastActive = time.Now()
	s.mu.Unlock()

	// Write client data to upstream.
	if op.Data != "" {
		payload, err := DecodeData(op.Data)
		if err != nil {
			return OpResult{SID: sid, Err: "data: bad base64"}
		}
		if len(payload) > 0 {
			_ = s.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_, err = s.conn.Write(payload)
			_ = s.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				m.closeSession(sid)
				return OpResult{SID: sid, Err: fmt.Sprintf("write: %v", err), EOF: boolPtr(true)}
			}
		}
	}

	// Read any pending upstream data.
	s.mu.Lock()
	data := s.readBuf
	s.readBuf = nil
	eof := s.eof
	s.mu.Unlock()

	r := OpResult{SID: sid, Data: EncodeData(data)}
	if eof {
		r.EOF = boolPtr(true)
		m.closeSession(sid)
	}
	return r
}

func (m *SessionManager) opClose(op Op) OpResult {
	sid := op.SID
	m.closeSession(sid)
	return OpResult{SID: sid, EOF: boolPtr(true)}
}

func (m *SessionManager) closeSession(sid string) {
	m.mu.Lock()
	s, ok := m.sessions[sid]
	if ok {
		delete(m.sessions, sid)
	}
	m.mu.Unlock()
	if ok {
		_ = s.conn.Close()
	}
}

func (m *SessionManager) readerLoop(sid string, s *session) {
	defer close(s.readDone)
	buf := make([]byte, 32768)
	for {
		_ = s.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := s.conn.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.readBuf = append(s.readBuf, buf[:n]...)
			s.lastActive = time.Now()
			s.mu.Unlock()
		}
		if err != nil {
			if err != io.EOF && !isTimeout(err) {
				// real error
			}
			if err == io.EOF || !isTimeout(err) {
				s.mu.Lock()
				s.eof = true
				s.mu.Unlock()
				return
			}
			// timeout — just loop and retry
		}
	}
}

// ReapIdle closes sessions idle longer than the configured timeout.
func (m *SessionManager) ReapIdle() int {
	m.mu.Lock()
	var stale []string
	for sid, s := range m.sessions {
		s.mu.Lock()
		idle := time.Since(s.lastActive)
		s.mu.Unlock()
		if idle > m.idleMax {
			stale = append(stale, sid)
		}
	}
	m.mu.Unlock()
	for _, sid := range stale {
		m.closeSession(sid)
	}
	return len(stale)
}

// Count returns the number of active sessions.
func (m *SessionManager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
