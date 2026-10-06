package wireproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
)

// HTTPServer is a forward proxy serving plain HTTP and HTTPS CONNECT.
//
// The previous implementation handled only GET and CONNECT, answered every
// other method with 405, closed the connection after a single response
// (breaking keep-alive), answered bad credentials with 401 (WinINET only
// understands 407 for proxy auth), and relayed through the raw conn while
// discarding bytes already buffered in its bufio.Reader. Windows clients
// (WinINET/WinHTTP) reuse connections and send POST/HEAD/OPTIONS requests,
// so they surfaced "connection closed" errors even though one-shot curl
// requests worked. This implementation supports all methods, keep-alive,
// hop-by-hop header stripping, and never loses buffered client bytes.
type HTTPServer struct {
	config *HTTPConfig

	dial func(network, address string) (net.Conn, error)

	auth         CredentialValidator
	logger       *device.Logger
	authRequired bool
}

const httpIdleTimeout = 5 * time.Minute

var httpHopByHopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// ListenAndServe creates a listener and serves proxy requests on it until
// the context is canceled or the listener fails.
func (s *HTTPServer) ListenAndServe(ctx context.Context, network, addr string) error {
	listener, err := net.Listen(network, addr)
	if err != nil {
		s.logger.Errorf("HTTP net.Listen failed: %v", err)
		return err
	}
	s.logger.Verbosef("HTTP listener bound successfully on %s", addr)

	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Verbosef("HTTP accept loop exited gracefully on listener close")
				return nil
			}
			s.logger.Errorf("HTTP accept error: %v", err)
			return err
		}
		go s.serveConn(conn)
	}
}

func (s *HTTPServer) serveConn(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	br := bufio.NewReader(conn)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(httpIdleTimeout))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Time{})

		if !s.authorized(req) {
			// 407 (not 401) is the only proxy auth status WinINET understands.
			s.writeSimpleResponse(
				conn,
				http.StatusProxyAuthRequired,
				map[string]string{"Proxy-Authenticate": `Basic realm="wireproxy"`},
			)
			return
		}

		if req.Method == http.MethodConnect {
			s.tunnel(req, conn, br)
			return
		}

		if !s.forward(req, conn, br) {
			return
		}
	}
}

func (s *HTTPServer) authorized(req *http.Request) bool {
	if !s.authRequired {
		return true
	}
	header := strings.TrimSpace(req.Header.Get("Proxy-Authorization"))
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Basic") {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(raw), ":")
	if !ok {
		return false
	}
	return s.auth.Valid(user, pass)
}

// forward proxies a plain HTTP request to the origin and relays the
// response. Returns true if the client connection should be reused.
func (s *HTTPServer) forward(req *http.Request, conn net.Conn, br *bufio.Reader) bool {
	if req.Host == "" {
		s.writeSimpleResponse(conn, http.StatusBadRequest, nil)
		return false
	}
	addr := req.Host
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "80")
	}

	peer, err := s.dial("tcp", addr)
	if err != nil {
		s.logger.Verbosef("HTTP proxy dial to %s failed: %v", addr, err)
		s.writeSimpleResponse(conn, http.StatusBadGateway, nil)
		return false
	}
	defer func() { _ = peer.Close() }()

	clientKeepAlive := requestWantsKeepAlive(req)
	// Protocol upgrades (plain WebSocket over ws://) are negotiated
	// end-to-end, so Connection/Upgrade must survive hop-by-hop stripping.
	upgradeValue := req.Header.Get("Upgrade")
	upgradeRequested :=
		upgradeValue != "" && strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
	// Expect is hop-by-hop: the client may withhold its body until it is
	// told to proceed, and the origin never sees Expect once stripped, so
	// we must answer 100 Continue ourselves — before reading the body.
	expectContinue := strings.EqualFold(req.Header.Get("Expect"), "100-continue")

	// Hop-by-hop (proxy) headers must not leak to origin servers.
	stripHopByHopHeaders(req.Header)

	if upgradeRequested {
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", upgradeValue)
	}
	if expectContinue {
		if _, err = io.WriteString(conn, "HTTP/1.1 100 Continue\r\n\r\n"); err != nil {
			return false
		}
	}

	// req.Write streams the request body as it reads; large uploads are
	// never buffered in full.
	if err = req.Write(peer); err != nil {
		return false
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}

	resp, err := http.ReadResponse(bufio.NewReader(peer), req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// A 101 response switches the connection to an opaque tunnel (e.g.
	// WebSocket). Connection/Upgrade headers must reach the client
	// verbatim, then the two sides are relayed bidirectionally.
	if resp.StatusCode == http.StatusSwitchingProtocols {
		if err = resp.Write(conn); err != nil {
			return false
		}
		s.relay(conn, peer, br)
		return false
	}

	keepAlive := clientKeepAlive && !resp.Close
	// Connection/framing headers are regenerated by resp.Write for the
	// client.
	resp.Header.Del("Connection")
	resp.Header.Del("Keep-Alive")
	resp.Header.Del("Proxy-Connection")
	resp.Header.Del("Transfer-Encoding")

	if resp.ContentLength < 0 && !req.ProtoAtLeast(1, 1) {
		// WinINET defaults to HTTP/1.0 through proxies ("Use HTTP 1.1
		// through proxy connections" is off by default), and chunked
		// responses are invalid for 1.0 clients. Re-frame as
		// close-delimited so streaming bodies (SSE, long-polling,
		// open-ended downloads) are forwarded as they arrive instead of
		// being buffered; the connection closes when the origin stream
		// ends.
		resp.TransferEncoding = nil
		resp.Close = true
		keepAlive = false
	} else {
		resp.Close = !keepAlive
	}

	// resp.Write streams the body as it arrives from the origin (never
	// buffered in full), so SSE events and other streamed chunks reach
	// the client as soon as the origin sends them.
	if err = resp.Write(conn); err != nil {
		return false
	}
	return keepAlive
}

// tunnel relays a CONNECT request bidirectionally.
func (s *HTTPServer) tunnel(req *http.Request, conn net.Conn, br *bufio.Reader) {
	addr := req.Host
	if addr == "" {
		addr = req.URL.Host
	}
	if addr == "" {
		s.writeSimpleResponse(conn, http.StatusBadRequest, nil)
		return
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "443")
	}

	peer, err := s.dial("tcp", addr)
	if err != nil {
		s.logger.Verbosef("HTTP CONNECT to %s failed: %v", addr, err)
		s.writeSimpleResponse(conn, http.StatusBadGateway, nil)
		return
	}
	defer func() { _ = peer.Close() }()

	if _, err = io.WriteString(conn, "HTTP/1.1 200 Connection established\r\nContent-Length: 0\r\n\r\n"); err != nil {
		return
	}

	s.relay(conn, peer, br)
}

// relay copies bidirectionally between the client and the origin after a
// CONNECT or a protocol upgrade. Bytes already buffered in br (read past
// the request headers) are delivered first so nothing is lost. Both
// directions copy through the shared 64KB buffer pool (see pool.go).
func (s *HTTPServer) relay(conn net.Conn, peer net.Conn, br *bufio.Reader) {
	go copyThenClose(peer, io.MultiReader(br, conn), peer)
	_ = copyBuffer(conn, peer)
}

func (s *HTTPServer) writeSimpleResponse(conn net.Conn, code int, extraHeaders map[string]string) {
	var b strings.Builder
	b.WriteString("HTTP/1.1 ")
	b.WriteString(strconv.Itoa(code))
	b.WriteByte(' ')
	b.WriteString(http.StatusText(code))
	b.WriteString("\r\n")
	for k, v := range extraHeaders {
		b.WriteString(k)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteString("\r\n")
	}
	b.WriteString("Content-Length: 0\r\nConnection: close\r\n\r\n")
	_, _ = conn.Write([]byte(b.String()))
}

func requestWantsKeepAlive(req *http.Request) bool {
	connection := strings.ToLower(req.Header.Get("Connection"))
	if strings.Contains(connection, "close") {
		return false
	}
	if req.ProtoAtLeast(1, 1) {
		return true
	}
	// HTTP/1.0 clients must opt in explicitly.
	return strings.Contains(connection, "keep-alive")
}

func stripHopByHopHeaders(h http.Header) {
	if c := h.Get("Connection"); c != "" {
		for _, token := range strings.Split(c, ",") {
			h.Del(strings.TrimSpace(token))
		}
	}
	for _, k := range httpHopByHopHeaders {
		h.Del(k)
	}
	h.Del("Expect")
}
