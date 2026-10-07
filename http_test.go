package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

func newTestHTTPServer(dial func(network, address string) (net.Conn, error), authRequired bool, username, password string) *HTTPServer {
	logger := device.NewLogger(device.LogLevelVerbose, "test")
	auth := CredentialValidator{username: username, password: password}
	return &HTTPServer{
		config:       &HTTPConfig{BindAddress: "", Username: username, Password: password},
		dial:         dial,
		auth:         auth,
		logger:       logger,
		authRequired: authRequired,
	}
}

func TestWriteSimpleResponse(t *testing.T) {
	tests := []struct {
		name       string
		code       int
		extra      map[string]string
		wantStatus int
		wantHeader string
	}{
		{
			name:       "407 with Proxy-Authenticate",
			code:       http.StatusProxyAuthRequired,
			extra:      map[string]string{"Proxy-Authenticate": `Basic realm="wireproxy"`},
			wantStatus: 407,
			wantHeader: "Proxy-Authenticate: Basic realm=\"wireproxy\"",
		},
		{
			name:       "502 no extra",
			code:       http.StatusBadGateway,
			extra:      nil,
			wantStatus: 502,
			wantHeader: "",
		},
		{
			name:       "400 with multiple extra",
			code:       http.StatusBadRequest,
			extra:      map[string]string{"X-Custom": "value1", "X-Another": "value2"},
			wantStatus: 400,
			wantHeader: "X-Custom: value1",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			conn := &mockConn{Writer: &buf}
			s := newTestHTTPServer(nil, false, "", "")
			s.writeSimpleResponse(conn, tc.code, tc.extra)

			// Save the raw response before parsing (ReadResponse consumes the buffer)
			raw := buf.String()
			t.Logf("buffer contents: %q", raw)

			// Parse the response to validate status code
			resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
			if err != nil {
				t.Fatalf("failed to parse response: %v", err)
			}
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d want %d", resp.StatusCode, tc.wantStatus)
			}
			// Check headers in the raw response (before it was consumed)
			if tc.wantHeader != "" {
				if !strings.Contains(raw, tc.wantHeader) {
					t.Fatalf("missing header %q in %q", tc.wantHeader, raw)
				}
			}
			// Should have Connection: close and Content-Length: 0
			if !strings.Contains(raw, "Connection: close") {
				t.Fatal("missing Connection: close")
			}
			if !strings.Contains(raw, "Content-Length: 0") {
				t.Fatal("missing Content-Length: 0")
			}
		})
	}
}

func TestWriteSimpleResponseLargeHeaders(t *testing.T) {
	// Build a response that exceeds 256 bytes to ensure heap fallback works
	extra := make(map[string]string)
	for i := 0; i < 10; i++ {
		extra["X-Long-Header-"+strings.Repeat("x", 20)] = strings.Repeat("y", 30)
	}
	var buf bytes.Buffer
	conn := &mockConn{Writer: &buf}
	s := newTestHTTPServer(nil, false, "", "")
	s.writeSimpleResponse(conn, 500, extra)

	resp, err := http.ReadResponse(bufio.NewReader(&buf), nil)
	if err != nil {
		t.Fatalf("failed to parse large response: %v", err)
	}
	if resp.StatusCode != 500 {
		t.Fatalf("status=%d want 500", resp.StatusCode)
	}
}

func TestAuthorized(t *testing.T) {
	logger := device.NewLogger(device.LogLevelSilent, "test")
	auth := CredentialValidator{username: "user", password: "pass"}
	s := &HTTPServer{
		auth:         auth,
		logger:       logger,
		authRequired: true,
	}

	tests := []struct {
		name     string
		authHdr  string
		expected bool
	}{
		{"valid credentials", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), true},
		{"wrong password", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:wrong")), false},
		{"wrong user", "Basic " + base64.StdEncoding.EncodeToString([]byte("wrong:pass")), false},
		{"malformed base64", "Basic notvalidbase64!", false},
		{"missing colon", "Basic " + base64.StdEncoding.EncodeToString([]byte("user")), false},
		{"wrong scheme", "Bearer " + base64.StdEncoding.EncodeToString([]byte("user:pass")), false},
		{"empty header", "", false},
		{"case-insensitive basic", "basic " + base64.StdEncoding.EncodeToString([]byte("user:pass")), true},
		{"extra spaces", "  Basic  " + base64.StdEncoding.EncodeToString([]byte("user:pass")) + "  ", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: http.Header{}}
			if tc.authHdr != "" {
				req.Header.Set("Proxy-Authorization", tc.authHdr)
			}
			if s.authorized(req) != tc.expected {
				t.Fatalf("authorized()=%v want %v", !tc.expected, tc.expected)
			}
		})
	}
}

func TestAuthorizedNoAuthRequired(t *testing.T) {
	logger := device.NewLogger(device.LogLevelSilent, "test")
	s := &HTTPServer{
		auth:         CredentialValidator{username: "user", password: "pass"},
		logger:       logger,
		authRequired: false,
	}
	req := &http.Request{Header: http.Header{}}
	if !s.authorized(req) {
		t.Fatal("authorized should be true when authRequired=false")
	}
}

func TestRequestWantsKeepAlive(t *testing.T) {
	tests := []struct {
		name     string
		proto    string
		connHdr  string
		expected bool
	}{
		{"HTTP/1.1 default", "HTTP/1.1", "", true},
		{"HTTP/1.1 explicit close", "HTTP/1.1", "close", false},
		{"HTTP/1.1 keep-alive header", "HTTP/1.1", "keep-alive", true},
		{"HTTP/1.0 default", "HTTP/1.0", "", false},
		{"HTTP/1.0 explicit keep-alive", "HTTP/1.0", "keep-alive", true},
		{"HTTP/1.0 close", "HTTP/1.0", "close", false},
		{"case insensitive close", "HTTP/1.1", "Close", false},
		{"multiple tokens", "HTTP/1.1", "keep-alive, upgrade", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// ProtoAtLeast uses ProtoMajor/ProtoMinor fields, not Proto string
			var major, minor int
			if tc.proto == "HTTP/1.1" {
				major, minor = 1, 1
			} else if tc.proto == "HTTP/1.0" {
				major, minor = 1, 0
			}
			req := &http.Request{
				Proto:      tc.proto,
				ProtoMajor: major,
				ProtoMinor: minor,
				Header:     http.Header{"Connection": []string{tc.connHdr}},
			}
			if requestWantsKeepAlive(req) != tc.expected {
				t.Fatalf("proto=%s conn=%q got %v want %v", tc.proto, tc.connHdr, !tc.expected, tc.expected)
			}
		})
	}
}

func TestStripHopByHopHeaders(t *testing.T) {
	h := http.Header{
		"Connection":          []string{"keep-alive, upgrade, custom"},
		"Proxy-Connection":    []string{"keep-alive"},
		"Keep-Alive":          []string{"timeout=5"},
		"Proxy-Authenticate":  []string{"Basic"},
		"Proxy-Authorization": []string{"Basic xyz"},
		"Te":                  []string{"trailers"},
		"Trailer":             []string{"X-Custom"},
		"Transfer-Encoding":   []string{"chunked"},
		"Upgrade":             []string{"websocket"},
		"Expect":              []string{"100-continue"},
		"Custom-Header":       []string{"should-stay"},
		"X-Another":           []string{"should-stay"},
	}
	stripHopByHopHeaders(h)

	// All hop-by-hop headers should be gone
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Expect",
	} {
		if h.Get(k) != "" {
			t.Fatalf("hop-by-hop header %s not stripped, value=%q", k, h.Get(k))
		}
	}
	// Connection-named tokens should also be stripped
	if h.Get("Custom") != "" {
		t.Fatal("Connection token 'custom' not stripped")
	}
	// Non-hop-by-hop should remain
	if h.Get("Custom-Header") != "should-stay" {
		t.Fatal("Custom-Header incorrectly stripped")
	}
	if h.Get("X-Another") != "should-stay" {
		t.Fatal("X-Another incorrectly stripped")
	}
}

func TestHTTPForwardSingleRequest(t *testing.T) {
	// Use a simple TCP origin server
	originListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originAddr := originListener.Addr().String()

	// Origin server that handles one request per connection
	go func() {
		for {
			conn, err := originListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				t.Logf("origin received: %s %s", req.Method, req.URL.Path)
				resp := "HTTP/1.1 200 OK\r\n" +
					"X-Origin: ok\r\n" +
					"Content-Length: 15\r\n" +
					"Connection: keep-alive\r\n" +
					"\r\n" +
					"origin-response"
				if _, err := c.Write([]byte(resp)); err != nil {
					return
				}
			}(conn)
		}
	}()
	defer originListener.Close()

	dial := func(network, address string) (net.Conn, error) {
		t.Logf("dialing origin: %s", originAddr)
		return net.Dial("tcp", originAddr)
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create listener for proxy server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Use Serve with our listener
	go func() {
		t.Logf("proxy server starting on %s", l.Addr())
		_ = s.Serve(ctx, l)
		t.Logf("proxy server stopped")
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req1 := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
	t.Logf("sending request")
	if _, err := conn.Write([]byte(req1)); err != nil {
		t.Fatal(err)
	}
	t.Logf("reading response")
	resp1, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("response status: %d", resp1.StatusCode)
	if resp1.StatusCode != 200 {
		t.Fatalf("status=%d want 200", resp1.StatusCode)
	}
	if resp1.Header.Get("X-Origin") != "ok" {
		t.Fatal("X-Origin header missing")
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()
}

func TestHTTPForwardKeepAlive(t *testing.T) {
	// Use a simple TCP origin server that we can control completely
	originListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originAddr := originListener.Addr().String()

	// Origin server that handles each connection and supports keep-alive
	go func() {
		for {
			conn, err := originListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					t.Logf("origin received: %s %s", req.Method, req.URL.Path)
					// Send response with keep-alive
					resp := "HTTP/1.1 200 OK\r\n" +
						"X-Origin: ok\r\n" +
						"Content-Length: 15\r\n" +
						"Connection: keep-alive\r\n" +
						"\r\n" +
						"origin-response"
					if _, err := c.Write([]byte(resp)); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	defer originListener.Close()

	dial := func(network, address string) (net.Conn, error) {
		t.Logf("dialing origin: %s", originAddr)
		return net.Dial("tcp", originAddr)
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create listener for proxy server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Use Serve with our listener
	go func() {
		t.Logf("proxy server starting on %s", l.Addr())
		_ = s.Serve(ctx, l)
		t.Logf("proxy server stopped")
	}()

	// Make two requests on the same connection to verify keep-alive
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Request 1
	req1 := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
	t.Logf("sending request 1")
	if _, err := conn.Write([]byte(req1)); err != nil {
		t.Fatal(err)
	}
	t.Logf("reading response 1")
	resp1, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("response 1 status: %d", resp1.StatusCode)
	if resp1.StatusCode != 200 {
		t.Fatalf("req1 status=%d want 200", resp1.StatusCode)
	}
	if resp1.Header.Get("X-Origin") != "ok" {
		t.Fatal("X-Origin header missing")
	}
	io.Copy(io.Discard, resp1.Body)
	resp1.Body.Close()

	// Request 2 on same connection
	req2 := "GET http://example.com/2 HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n"
	t.Logf("sending request 2")
	if _, err := conn.Write([]byte(req2)); err != nil {
		t.Fatal(err)
	}
	t.Logf("reading response 2")
	resp2, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("response 2 status: %d", resp2.StatusCode)
	if resp2.StatusCode != 200 {
		t.Fatalf("req2 status=%d want 200", resp2.StatusCode)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
}

func TestHTTPForwardHopByHopStripped(t *testing.T) {
	// Use a simple TCP origin server that verifies hop-by-hop headers are NOT present
	originListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originAddr := originListener.Addr().String()

	go func() {
		for {
			conn, err := originListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				// Check that hop-by-hop headers are not present
				for _, k := range []string{
					"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
					"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade", "Expect",
				} {
					if req.Header.Get(k) != "" {
						t.Logf("leaked header: %s = %q", k, req.Header.Get(k))
						resp := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
						c.Write([]byte(resp))
						return
					}
				}
				resp := "HTTP/1.1 200 OK\r\n" +
					"X-Origin: ok\r\n" +
					"Content-Length: 2\r\n" +
					"\r\n" +
					"ok"
				c.Write([]byte(resp))
			}(conn)
		}
	}()
	defer originListener.Close()

	dial := func(network, address string) (net.Conn, error) {
		return net.Dial("tcp", originAddr)
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = s.Serve(ctx, l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send Upgrade header WITHOUT "upgrade" in Connection to test stripping
	// (if "upgrade" is in Connection, the proxy treats it as a real upgrade request)
	req := "GET http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Connection: keep-alive\r\n" +
		"Proxy-Connection: keep-alive\r\n" +
		"Keep-Alive: timeout=5\r\n" +
		"Proxy-Authorization: Basic xyz\r\n" +
		"Te: trailers\r\n" +
		"Trailer: X-Custom\r\n" +
		"Upgrade: websocket\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestHTTPForwardPOSTBody(t *testing.T) {
	bodyReceived := make(chan string, 1)

	// Use a simple TCP origin server
	originListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originAddr := originListener.Addr().String()

	go func() {
		for {
			conn, err := originListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				body, _ := io.ReadAll(req.Body)
				bodyReceived <- string(body)
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
				c.Write([]byte(resp))
			}(conn)
		}
	}()
	defer originListener.Close()

	dial := func(network, address string) (net.Conn, error) {
		return net.Dial("tcp", originAddr)
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = s.Serve(ctx, l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	body := "hello world"
	req := "POST http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
		"\r\n" + body
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	select {
	case received := <-bodyReceived:
		if received != body {
			t.Fatalf("origin received %q want %q", received, body)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for body")
	}
}

func TestHTTPProxyAuthRequired(t *testing.T) {
	dial := func(network, address string) (net.Conn, error) {
		return nil, errors.New("should not dial")
	}

	s := newTestHTTPServer(dial, true, "user", "pass")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = s.Serve(ctx, l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// No auth header
	req := "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status=%d want 407", resp.StatusCode)
	}
	if resp.Header.Get("Proxy-Authenticate") == "" {
		t.Fatal("missing Proxy-Authenticate header")
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestHTTPBadGatewayOnDialFailure(t *testing.T) {
	dial := func(network, address string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = s.Serve(ctx, l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	req := "GET http://unreachable/ HTTP/1.1\r\nHost: unreachable\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d want 502", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
}

func TestHTTPCONNECTTunnel(t *testing.T) {
	// Echo server for tunnel
	echo := &echoServer{}
	go echo.listen()
	echo.waitReady()
	defer echo.close()

	dial := func(network, address string) (net.Conn, error) {
		return net.Dial("tcp", echo.addr)
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = s.Serve(ctx, l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// CONNECT request (no Host header for CONNECT)
	req := "CONNECT " + echo.addr + " HTTP/1.1\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status=%d want 200", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Now tunnel is established; send data through it
	testMsg := "hello through tunnel"
	if _, err := conn.Write([]byte(testMsg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(testMsg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != testMsg {
		t.Fatalf("echo got %q want %q", string(buf), testMsg)
	}
}

func TestHTTPExpectContinue(t *testing.T) {
	// Use a simple TCP origin server
	originListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	originAddr := originListener.Addr().String()

	go func() {
		for {
			conn, err := originListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				// Read body if present
				io.Copy(io.Discard, req.Body)
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
				c.Write([]byte(resp))
			}(conn)
		}
	}()
	defer originListener.Close()

	dial := func(network, address string) (net.Conn, error) {
		return net.Dial("tcp", originAddr)
	}

	s := newTestHTTPServer(dial, false, "", "")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		_ = s.Serve(ctx, l)
	}()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Request with Expect: 100-continue
	req := "POST http://example.com/ HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Expect: 100-continue\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	// Should receive 100 Continue first
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 100 {
		t.Fatalf("first response status=%d want 100", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Now send body
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	// Read final response
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp2.StatusCode != 200 {
		t.Fatalf("final status=%d want 200", resp2.StatusCode)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()
}

func readBody(resp *http.Response) string {
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

// mockConn implements net.Conn for testing writeSimpleResponse
type mockConn struct {
	*bytes.Buffer
	Writer io.Writer
}

func (m *mockConn) Read(p []byte) (int, error)         { return 0, io.EOF }
func (m *mockConn) Write(p []byte) (int, error)        { return m.Writer.Write(p) }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// echoServer is a simple TCP echo server for CONNECT tunnel testing
type echoServer struct {
	listener net.Listener
	addr     string
	mu       sync.Mutex
}

func (e *echoServer) listen() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	e.mu.Lock()
	e.listener = l
	e.addr = l.Addr().String()
	e.mu.Unlock()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go io.Copy(conn, conn)
		}
	}()
}

// waitReady waits until the server is ready to accept connections
// by attempting a test connection
func (e *echoServer) waitReady() {
	for {
		e.mu.Lock()
		addr := e.addr
		e.mu.Unlock()
		if addr == "" {
			time.Sleep(time.Millisecond)
			continue
		}
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func (e *echoServer) close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.listener != nil {
		_ = e.listener.Close()
	}
}
