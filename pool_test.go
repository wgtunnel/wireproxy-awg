package wireproxy

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestBufPoolGetPut(t *testing.T) {
	b := buffers.Get()
	if cap(b) != bufSize {
		t.Fatalf("cap=%d want %d", cap(b), bufSize)
	}
	buffers.Put(b)

	// Re-get should return the same capacity buffer
	b2 := buffers.Get()
	if cap(b2) != bufSize {
		t.Fatalf("cap=%d want %d", cap(b2), bufSize)
	}
	buffers.Put(b2)
}

func TestBufPoolPutDropsForeignBuffer(t *testing.T) {
	foreign := make([]byte, 100)
	buffers.Put(foreign)
	// Pool should not be poisoned; next Get still works
	b := buffers.Get()
	if cap(b) != bufSize {
		t.Fatalf("cap=%d want %d after foreign Put", cap(b), bufSize)
	}
	buffers.Put(b)
}

func TestBufPoolPutDropsResizedBuffer(t *testing.T) {
	b := buffers.Get()
	b = b[:10] // resize slice
	buffers.Put(b)
	// Pool should not be poisoned
	b2 := buffers.Get()
	if cap(b2) != bufSize {
		t.Fatalf("cap=%d want %d after resized Put", cap(b2), bufSize)
	}
	buffers.Put(b2)
}

func TestCopyBufferZeroSources(t *testing.T) {
	var dst bytes.Buffer
	if err := copyBuffer(&dst); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.Len() != 0 {
		t.Fatalf("dst should be empty, got %d bytes", dst.Len())
	}
}

func TestCopyBufferSingleSource(t *testing.T) {
	src := bytes.NewReader([]byte("hello"))
	var dst bytes.Buffer
	if err := copyBuffer(&dst, src); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.String() != "hello" {
		t.Fatalf("got %q want %q", dst.String(), "hello")
	}
}

func TestCopyBufferMultipleSourcesOrder(t *testing.T) {
	src1 := bytes.NewReader([]byte("abc"))
	src2 := bytes.NewReader([]byte("def"))
	src3 := bytes.NewReader([]byte("ghi"))
	var dst bytes.Buffer
	if err := copyBuffer(&dst, src1, src2, src3); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dst.String() != "abcdefghi" {
		t.Fatalf("got %q want %q", dst.String(), "abcdefghi")
	}
}

func TestCopyBufferErrorPropagation(t *testing.T) {
	errSrc := &errorReader{err: errors.New("boom")}
	var dst bytes.Buffer
	err := copyBuffer(&dst, errSrc)
	if err == nil || err.Error() != "boom" {
		t.Fatalf("expected error 'boom', got %v", err)
	}
}

func TestCopyThenCloseClosesAfterCopy(t *testing.T) {
	var closed bool
	closer := &mockCloser{closeFn: func() error { closed = true; return nil }}
	src := bytes.NewReader([]byte("data"))
	var dst bytes.Buffer
	copyThenClose(&dst, closer, src)
	if !closed {
		t.Fatal("closer not closed after copy")
	}
	if dst.String() != "data" {
		t.Fatalf("got %q want %q", dst.String(), "data")
	}
}

func TestCopyThenCloseNilCloser(t *testing.T) {
	src := bytes.NewReader([]byte("data"))
	var dst bytes.Buffer
	copyThenClose(&dst, nil, src)
	if dst.String() != "data" {
		t.Fatalf("got %q want %q", dst.String(), "data")
	}
}

func TestCopyThenCloseMultipleSources(t *testing.T) {
	var closed bool
	closer := &mockCloser{closeFn: func() error { closed = true; return nil }}
	src1 := bytes.NewReader([]byte("a"))
	src2 := bytes.NewReader([]byte("b"))
	var dst bytes.Buffer
	copyThenClose(&dst, closer, src1, src2)
	if !closed {
		t.Fatal("closer not closed after copy")
	}
	if dst.String() != "ab" {
		t.Fatalf("got %q want %q", dst.String(), "ab")
	}
}

func TestCopyBufferConcurrentPoolReuse(t *testing.T) {
	const workers = 10
	const iterations = 100
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				src := bytes.NewReader([]byte("x"))
				var dst bytes.Buffer
				if err := copyBuffer(&dst, src); err != nil {
					errCh <- err
					return
				}
				if dst.String() != "x" {
					errCh <- errors.New("data mismatch")
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent error: %v", err)
	}
}

type mockCloser struct {
	closeFn func() error
}

func (m *mockCloser) Close() error {
	if m.closeFn != nil {
		return m.closeFn()
	}
	return nil
}

type errorReader struct {
	err error
}

func (e *errorReader) Read(p []byte) (int, error) {
	return 0, e.err
}
