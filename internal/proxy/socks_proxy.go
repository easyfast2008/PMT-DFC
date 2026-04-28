// Package proxy hosts the local SOCKS5 listener. Kept for backward
// compatibility — the cmd/client now handles SOCKS5 directly using the
// batch multiplexer. This package is retained as a thin convenience
// wrapper for callers that still want a standalone proxy server.
package proxy
