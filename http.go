package wireproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/amnezia-vpn/amneziawg-go/device"
)

const proxyAuthHeaderKey = "Proxy-Authorization"

type HTTPServer struct {
	config *HTTPConfig

	auth CredentialValidator
	dial func(network, address string) (net.Conn, error)

	logger       *device.Logger
	authRequired bool
}

func (s *HTTPServer) authenticate(req *http.Request) (int, error) {
	if !s.authRequired {
		return 0, nil
	}

	auth := req.Header.Get(proxyAuthHeaderKey)
	if auth == "" {
		return http.StatusProxyAuthRequired, fmt.Errorf("%s", http.StatusText(http.StatusProxyAuthRequired))
	}

	enc := strings.TrimPrefix(auth, "Basic ")
	str, err := base64.StdEncoding.DecodeString(enc)
	if err != nil {
		return http.StatusNotAcceptable, fmt.Errorf("decode username and password failed: %w", err)
	}
	pairs := bytes.SplitN(str, []byte(":"), 2)
	if len(pairs) != 2 {
		return http.StatusLengthRequired, fmt.Errorf("username and password format invalid")
	}
	if s.auth.Valid(string(pairs[0]), string(pairs[1])) {
		return 0, nil
	}
	return http.StatusUnauthorized, fmt.Errorf("username and password not matching")
}

func (s *HTTPServer) handleConn(req *http.Request, conn net.Conn) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "443"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	_, err = conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		_ = peer.Close()
		peer = nil
	}

	return
}

func (s *HTTPServer) handle(req *http.Request) (peer net.Conn, err error) {
	addr := req.Host
	if !strings.Contains(addr, ":") {
		port := "80"
		addr = net.JoinHostPort(addr, port)
	}

	peer, err = s.dial("tcp", addr)
	if err != nil {
		return peer, fmt.Errorf("tun tcp dial failed: %w", err)
	}

	err = req.Write(peer)
	if err != nil {
		_ = peer.Close()
		peer = nil
		return peer, fmt.Errorf("conn write failed: %w", err)
	}

	return
}

func (s *HTTPServer) serve(conn net.Conn) {
	var rd = bufio.NewReader(conn)
	req, err := http.ReadRequest(rd)
	if err != nil {
		s.logger.Errorf("HTTP read request failed: %v", err)
		return
	}

	code, err := s.authenticate(req)
	if err != nil {
		resp := responseWith(req, code)
		if code == http.StatusProxyAuthRequired {
			resp.Header.Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		}
		_ = resp.Write(conn)
		s.logger.Errorf("HTTP authentication failed: %v", err)
		return
	}

	var peer net.Conn
	switch req.Method {
	case http.MethodConnect:
		peer, err = s.handleConn(req, conn)
	case http.MethodGet:
		peer, err = s.handle(req)
	default:
		_ = responseWith(req, http.StatusMethodNotAllowed).Write(conn)
		s.logger.Errorf("HTTP unsupported protocol: %s", req.Method)
		return
	}
	if err != nil {
		s.logger.Errorf("HTTP handle failed: %v", err)
		return
	}
	if peer == nil {
		s.logger.Errorf("HTTP handle failed: peer nil")
		return
	}

	go func() {
		defer conn.Close()
		defer peer.Close()

		_, _ = io.Copy(conn, peer)
	}()

	go func() {
		defer conn.Close()
		defer peer.Close()

		_, _ = io.Copy(peer, conn)
	}()
}

// ListenAndServe is used to create a listener and serve on it
func (s *HTTPServer) ListenAndServe(ctx context.Context, network, addr string) error {
	listener, err := net.Listen(network, addr)
	if err != nil {
		s.logger.Errorf("HTTP net.Listen failed: %v", err)
		return err
	}
	s.logger.Verbosef("HTTP listener bound successfully on %s", addr)

	errCh := make(chan error, 1)
	go func() {
		s.logger.Verbosef("HTTP accept loop started")
		for {
			conn, err := listener.Accept()
			if err != nil {
				s.logger.Errorf("HTTP accept error: %v", err)
				errCh <- err
				return
			}
			go func(conn net.Conn) {
				defer func() {
					if err := conn.Close(); err != nil {
						s.logger.Errorf("HTTP connection close failed: %v", err)
					}
				}()
				s.serve(conn)
			}(conn)
		}
	}()

	select {
	case err := <-errCh:
		if closeErr := listener.Close(); closeErr != nil {
			s.logger.Errorf("HTTP listener close failed: %v", closeErr)
		}
		if err != nil {
			s.logger.Errorf("HTTP ListenAndServe error: %v", err)
		}
		return err
	case <-ctx.Done():
		s.logger.Verbosef("HTTP ListenAndServe context done: %v", ctx.Err())
		if err := listener.Close(); err != nil {
			s.logger.Errorf("HTTP listener close failed: %v", err)
		}
		<-errCh // Drain to wait for goroutine exit (ignores the triggered accept error)
		return ctx.Err()
	}
}
