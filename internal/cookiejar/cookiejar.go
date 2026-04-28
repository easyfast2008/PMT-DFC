// Package cookiejar will host the per-session cookie store used by the
// headless-browser exit (Phase 2).
//
// Phase 1 does not need this: the SOCKS5 raw-TCP exit transparently relays
// the client's own TLS connection to the target, so the client retains its
// own cookies natively. Cookies only become a server-side concern when a
// headless browser at the exit performs requests on the client's behalf,
// at which point continuity must be maintained per-session.
//
// This file intentionally has no implementation. A future jar should:
//
//   - key by an opaque session id supplied by the client over an inner
//     control stream;
//   - persist to GCS or Firestore so warm sessions survive Cloud Run
//     instance recycling;
//   - cap memory usage and evict idle sessions.
package cookiejar
