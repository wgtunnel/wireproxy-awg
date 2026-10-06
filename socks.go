package wireproxy

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/things-go/go-socks5"
)

// Windows Internet Options (WinINET) only ever implemented SOCKS4/4a, so a
// SOCKS5-only listener immediately closes Windows connections (go-socks5
// expects version byte 0x05 and rejects 0x04). serveSocksConn multiplexes
// both families on one port by peeking the version byte.

const (
	socksVersion4             = 0x04
	socksVersion5             = 0x05
	socks4RequestGranted      = 0x5a
	socks4RequestRejected     = 0x5b
	socks4ConnectCommand      = 0x01
	socks4GreetingReadTimeout = 30 * time.Second
	socks4MaxFieldLength      = 512
)

// serveSocksConn dispatches one accepted connection to the SOCKS5 server or
// the SOCKS4/4a handler based on the leading version byte.
func serveSocksConn(server *socks5.Server, dialer *tunDialer, logger *device.Logger, conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Errorf("SOCKS network connect close failed: %v", err)
		}
	}()

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(socks4GreetingReadTimeout))
	version, err := br.Peek(1)
	if err != nil || len(version) == 0 {
		return
	}
	_ = conn.SetReadDeadline(time.Time{})

	switch version[0] {
	case socksVersion5:
		if err = server.ServeConn(bufioConn{conn, br}); err != nil && !isBenignConnError(err) {
			logger.Errorf("SOCKS5 ServeConn error for %s: %v", conn.RemoteAddr(), err)
		}
	case socksVersion4:
		serveSocks4(dialer, logger, conn, br)
	default:
		logger.Errorf("SOCKS unsupported protocol version %d from %s", version[0], conn.RemoteAddr())
	}
}

// bufioConn lets go-socks5 read from the shared bufio.Reader so bytes
// already buffered during version detection are not lost.
type bufioConn struct {
	net.Conn
	br *bufio.Reader
}

func (c bufioConn) Read(p []byte) (int, error) { return c.br.Read(p) }

// serveSocks4 handles SOCKS4 and SOCKS4a CONNECT requests (WinINET-compatible).
func serveSocks4(dialer *tunDialer, logger *device.Logger, conn net.Conn, br *bufio.Reader) {
	var header [8]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return
	}

	command := header[1]
	port := binary.BigEndian.Uint16(header[2:4])
	rawIP := net.IP(header[4:8])

	// The userid field carries no credential the shared proxy configuration
	// could check (SOCKS4 has no password support at all), so SOCKS4 requests
	// are served even when credentials are configured for SOCKS5. The field
	// must still be consumed for framing before the optional 4a hostname.
	if _, err := readSocks4Field(br); err != nil {
		return
	}

	if command != socks4ConnectCommand {
		writeSocks4Reply(conn, socks4RequestRejected)
		return
	}

	// SOCKS4a: 0.0.0.x (nonzero final octet) means the hostname follows.
	var host string
	if len(rawIP) == 4 && rawIP[0] == 0 && rawIP[1] == 0 && rawIP[2] == 0 && rawIP[3] != 0 {
		domain, err := readSocks4Field(br)
		if err != nil {
			return
		}
		host = string(domain)
	} else {
		host = rawIP.String()
	}

	addr := net.JoinHostPort(host, strconv.Itoa(int(port)))
	peer, err := dialer.Dial("tcp", addr)
	if err != nil {
		logger.Verbosef("SOCKS4 dial to %s failed: %v", addr, err)
		writeSocks4Reply(conn, socks4RequestRejected)
		return
	}
	defer func() { _ = peer.Close() }()

	writeSocks4Reply(conn, socks4RequestGranted)

	// Both directions copy through the shared 64KB buffer pool (pool.go);
	// br and conn are passed as separate sources so no io.MultiReader is
	// allocated per relayed connection.
	go copyThenClose(peer, peer, br, conn)
	_ = copyBuffer(conn, peer)
}

func writeSocks4Reply(conn net.Conn, code byte) {
	_, _ = conn.Write([]byte{0x00, code, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

func readSocks4Field(r io.Reader) ([]byte, error) {
	var (
		out  []byte
		next [1]byte
	)
	for {
		if _, err := io.ReadFull(r, next[:]); err != nil {
			return nil, err
		}
		if next[0] == 0x00 {
			return out, nil
		}
		out = append(out, next[0])
		if len(out) > socks4MaxFieldLength {
			return nil, errors.New("socks4 field too long")
		}
	}
}

func isBenignConnError(err error) bool {
	if err == nil {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "connection aborted") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "operation aborted")
}
