// Package tunnel implements the batch JSON protocol for tunneling TCP
// sessions through an HTTP relay (Google Apps Script or Cloudflare Worker).
//
// Wire format is compatible with MhR's tunnel-node:
//
//	POST /tunnel/batch
//	{"k":"auth_key","ops":[...]}
//	→ {"r":[...]}
//
// Each batch carries multiple session operations (connect, data, close)
// so one HTTP round trip serves many concurrent TCP streams.
package tunnel

import (
	"encoding/base64"
)

// Op is a single operation in a batch request.
type Op struct {
	Op   string `json:"op"`             // "connect", "data", "close"
	SID  string `json:"sid,omitempty"`  // session ID (UUID)
	Host string `json:"host,omitempty"` // target host (connect only)
	Port uint16 `json:"port,omitempty"` // target port (connect only)
	Data string `json:"d,omitempty"`    // base64-encoded payload
}

// BatchRequest is the top-level request from client → relay → VPS.
type BatchRequest struct {
	Key string `json:"k"`    // auth key
	Ops []Op   `json:"ops"`  // operations
}

// OpResult is one result in a batch response.
type OpResult struct {
	SID  string `json:"sid,omitempty"`
	Data string `json:"d,omitempty"`   // base64-encoded response data
	EOF  *bool  `json:"eof,omitempty"` // true when session closed
	Err  string `json:"e,omitempty"`   // error message
}

// BatchResponse is the top-level response from VPS → relay → client.
type BatchResponse struct {
	Results []OpResult `json:"r"`
	Error   string     `json:"e,omitempty"`
}

// EncodeData encodes raw bytes as base64 for the wire.
func EncodeData(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeData decodes a base64 wire string back to bytes.
func DecodeData(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}

func boolPtr(v bool) *bool { return &v }
