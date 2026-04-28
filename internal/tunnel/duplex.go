package tunnel

import (
	"errors"
	"io"
	"net/http"
	"sync"
)

// duplexHTTP2 adapts an HTTP/2 streaming-POST exchange into an
// io.ReadWriteCloser so it can carry yamux frames.
//
// On the server side: reads come from r.Body, writes go to w (flushed each
// time so frames hit the wire promptly).
//
// On the client side: reads come from resp.Body, writes go through an
// io.Pipe whose read end was passed as the request body to the transport.
type duplexHTTP2 struct {
	r io.ReadCloser
	w io.Writer

	flusher http.Flusher
	closer  io.Closer

	closeOnce sync.Once
	closeErr  error
}

func (d *duplexHTTP2) Read(p []byte) (int, error) {
	return d.r.Read(p)
}

func (d *duplexHTTP2) Write(p []byte) (int, error) {
	n, err := d.w.Write(p)
	if err != nil {
		return n, err
	}
	if d.flusher != nil {
		d.flusher.Flush()
	}
	return n, nil
}

func (d *duplexHTTP2) Close() error {
	d.closeOnce.Do(func() {
		var errs []error
		if d.r != nil {
			if err := d.r.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		if d.closer != nil {
			if err := d.closer.Close(); err != nil {
				errs = append(errs, err)
			}
		}
		d.closeErr = errors.Join(errs...)
	})
	return d.closeErr
}
