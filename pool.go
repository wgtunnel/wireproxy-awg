package wireproxy

import (
	"io"
	"sync"
)

// bufSize is the size of every buffer handed out by the shared pool. 64KB
// keeps bulk relay reads large (fewer syscalls per byte on the netstack)
// while bounding per-connection memory to one buffer per copy direction.
const bufSize = 64 * 1024

// bufPool is the shared buffer pool for all proxy relay paths. HTTP CONNECT
// tunnels, 101 protocol upgrades, plain-HTTP relays, SOCKS relays and
// go-socks5 (via its bufferpool.BufPool interface) all draw from it, so
// buffers are reused aggressively across thousands of connections instead
// of being reallocated per connection.
type bufPool struct {
	pool sync.Pool
}

var buffers = bufPool{pool: sync.Pool{New: newBuf}}

func newBuf() any {
	b := make([]byte, bufSize)
	return &b
}

// Get returns a bufSize buffer. The method set (Get/Put) satisfies
// go-socks5's bufferpool.BufPool, which is how the SOCKS server ends up
// sharing this same pool.
func (p *bufPool) Get() []byte {
	b := p.pool.Get().(*[]byte)
	return *b
}

// Put returns a buffer to the pool. Foreign or resized slices are dropped
// rather than pooled so a bad caller cannot poison every other user of
// the pool.
func (p *bufPool) Put(b []byte) {
	if cap(b) != bufSize {
		return
	}
	s := b[:bufSize]
	p.pool.Put(&s)
}

// copyBuffer copies srcs to dst, in order, through a single pooled 64KB
// buffer so no per-connection io.Copy scratch buffers are allocated.
// Accepting the sources directly (instead of forcing callers to wrap
// them in an io.MultiReader) keeps the relay hot path allocation-free:
// MultiReader would heap-allocate a wrapper per relayed connection just
// to chain the sources, and it would also defeat io.CopyBuffer's fast
// paths, since the MultiReader itself implements neither ReaderFrom nor
// WriterTo. Reading each source to EOF in turn is otherwise identical
// to what MultiReader does.
func copyBuffer(dst io.Writer, srcs ...io.Reader) error {
	var buf []byte
	for _, src := range srcs {
		// Preserve io.Copy's zero-copy fast paths for the common
		// single-source relay: src.WriteTo / dst.ReadFrom.
		if _, ok := src.(io.WriterTo); ok {
			if _, err := io.Copy(dst, src); err != nil {
				return err
			}
			continue
		} else if _, ok := dst.(io.ReaderFrom); ok {
			if _, err := io.Copy(dst, src); err != nil {
				return err
			}
			continue
		}

		if cap(buf) == 0 {
			buf = buffers.Get()
			defer buffers.Put(buf)
		}

		if _, err := io.CopyBuffer(dst, src, buf); err != nil {
			return err
		}
	}

	return nil
}

// copyThenClose copies srcs to dst through a pooled buffer and then closes
// closeAfter, which unblocks the opposite-direction copy that is still
// reading from the same connection. Multiple source readers are drained
// in order, so callers can chain buffered leftover bytes with the raw
// connection without allocating an io.MultiReader.
func copyThenClose(dst io.Writer, closeAfter io.Closer, srcs ...io.Reader) {
	_ = copyBuffer(dst, srcs...)
	if closeAfter != nil {
		_ = closeAfter.Close()
	}
}
