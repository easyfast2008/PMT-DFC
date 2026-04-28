package exit

// Headless is a placeholder for a headless-browser exit (Phase 2).
//
// The intended design:
//
//   - A pool of chromedp / playwright Chromium contexts inside the
//     Cloud Run container.
//   - Per-session-id cookie jars keyed by an opaque sid carried in a
//     side-channel (e.g. an inner control stream multiplexed into yamux).
//   - When the SOCKS handler observes a CONNECT to a known anti-bot
//     domain (or detects a 403 + challenge HTML pattern after attempting
//     a direct dial), it routes the request through this dialer instead.
//   - The headless dialer does NOT return a raw TCP socket. Instead it
//     opens a virtual conn that speaks HTTPS — i.e. it terminates TLS
//     locally with the browser and replays the request inside the browser
//     context. Implementing this requires intercepting the inner TLS
//     handshake, which in turn means the client must be configured to
//     trust a tunnel-managed CA. This is left to Phase 2 because it is a
//     significant security and UX surface.
//
// For now this package exposes only the stub so that the rest of the
// system can be wired against the Dialer interface without scaffolding
// the full headless infrastructure.
