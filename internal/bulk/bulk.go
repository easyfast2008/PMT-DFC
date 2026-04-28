// Package bulk will implement the dual-lane traffic split (Phase 3) that
// offloads large responses to Google Cloud Storage so that big downloads
// don't head-of-line block the interactive multiplex.
//
// Sketch:
//
//   - The server detects responses larger than a threshold (configurable,
//     default 1 MiB).
//   - It uploads them to a private GCS bucket and returns a signed URL on
//     the inner stream.
//   - The client fetches the signed URL through the same fronted-TLS
//     channel (storage.googleapis.com is also GFE-fronted).
//   - The client splices the GCS body back to the original requester
//     transparently.
//
// Cost note: GCS egress is cheaper than Cloud Run egress and benefits
// from the global edge cache. The signed URLs SHOULD be short-lived
// (≤5 min) and bound to the requesting session.
//
// This package is an intentional stub; see Docs/architecture.md §7.
package bulk
