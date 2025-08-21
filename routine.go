package wireproxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math/rand"
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	srand "crypto/rand"

	"github.com/things-go/go-socks5"
	"github.com/things-go/go-socks5/bufferpool"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// RoutineSpawner spawns a routine (e.g. socks5, tcp static routes) after the configuration is parsed
type RoutineSpawner interface {
	SpawnRoutine(ctx context.Context, vt *VirtualTun) error
}

// CredentialValidator stores the authentication data of a socks5 proxy
type CredentialValidator struct {
	username string
	password string
}

// Valid checks the authentication data in CredentialValidator and compare them
// to username and password in constant time.
func (c CredentialValidator) Valid(username, password string) bool {
	u := subtle.ConstantTimeCompare([]byte(c.username), []byte(username))
	p := subtle.ConstantTimeCompare([]byte(c.password), []byte(password))
	return u&p == 1
}

func (d *VirtualTun) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.Logger.Verbosef("Health metric request: %s", r.URL.Path)
	switch path.Clean(r.URL.Path) {
	case "/readyz":
		body, err := json.Marshal(d.PingRecord)
		if err != nil {
			d.Logger.Errorf("Failed to get device metrics: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		status := http.StatusOK
		for _, record := range d.PingRecord {
			lastPong := time.Unix(int64(record), 0)
			// +2 seconds to account for the time it takes to ping the IP
			if time.Since(lastPong) > time.Duration(d.Conf.CheckAliveInterval+2)*time.Second {
				status = http.StatusServiceUnavailable
				break
			}
		}

		w.WriteHeader(status)
		_, _ = w.Write(body)
		_, _ = w.Write([]byte("\n"))
	case "/metrics":
		get, err := d.Dev.IpcGet()
		if err != nil {
			d.Logger.Errorf("Failed to get device metrics: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var buf bytes.Buffer
		for _, peer := range strings.Split(get, "\n") {
			pair := strings.SplitN(peer, "=", 2)
			if len(pair) != 2 {
				buf.WriteString(peer)
				continue
			}
			if pair[0] == "private_key" || pair[0] == "preshared_key" {
				pair[1] = "REDACTED"
			}
			buf.WriteString(pair[0])
			buf.WriteString("=")
			buf.WriteString(pair[1])
			buf.WriteString("\n")
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (d *VirtualTun) pingIPs() {
	for _, addr := range d.Conf.CheckAlive {
		socket, err := d.Tnet.Dial("ping", addr.String())
		if err != nil {
			d.Logger.Errorf("Failed to ping %s: %v", addr, err)
			continue
		}

		data := make([]byte, 16)
		_, _ = srand.Read(data)

		requestPing := icmp.Echo{
			Seq:  rand.Intn(1 << 16),
			Data: data,
		}

		var icmpBytes []byte
		if addr.Is4() {
			icmpBytes, _ = (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: &requestPing}).Marshal(nil)
		} else if addr.Is6() {
			icmpBytes, _ = (&icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Code: 0, Body: &requestPing}).Marshal(nil)
		} else {
			d.Logger.Errorf("Failed to ping %s: invalid address: %s", addr, addr.String())
			continue
		}

		_ = socket.SetReadDeadline(time.Now().Add(time.Duration(d.Conf.CheckAliveInterval) * time.Second))
		_, err = socket.Write(icmpBytes)
		if err != nil {
			d.Logger.Errorf("Failed to ping %s: %v", addr, err)
			continue
		}

		addr := addr
		go func() {
			n, err := socket.Read(icmpBytes[:])
			if err != nil {
				d.Logger.Errorf("Failed to read ping response from %s: %v", addr, err)
				return
			}

			replyPacket, err := icmp.ParseMessage(1, icmpBytes[:n])
			if err != nil {
				d.Logger.Errorf("Failed to parse ping response from %s: %v", addr, err)
				return
			}

			if addr.Is4() {
				replyPing, ok := replyPacket.Body.(*icmp.Echo)
				if !ok {
					d.Logger.Errorf("Failed to parse ping response from %s: invalid reply type: %s", addr, replyPacket.Type)
					return
				}
				if !bytes.Equal(replyPing.Data, requestPing.Data) || replyPing.Seq != requestPing.Seq {
					d.Logger.Errorf("Failed to parse ping response from %s: invalid ping reply: %v", addr, replyPing)
					return
				}
			}

			if addr.Is6() {
				replyPing, ok := replyPacket.Body.(*icmp.RawBody)
				if !ok {
					d.Logger.Errorf("Failed to parse ping response from %s: invalid reply type: %s", addr, replyPacket.Type)
					return
				}

				seq := binary.BigEndian.Uint16(replyPing.Data[2:4])
				pongBody := replyPing.Data[4:]
				if !bytes.Equal(pongBody, requestPing.Data) || int(seq) != requestPing.Seq {
					d.Logger.Errorf("Failed to parse ping response from %s: invalid ping reply: %v", addr, replyPing)
					return
				}
			}

			d.PingRecordLock.Lock()
			d.PingRecord[addr.String()] = uint64(time.Now().Unix())
			d.PingRecordLock.Unlock()

			defer socket.Close()
		}()
	}
}

func (d *VirtualTun) StartPingIPs() {
	for _, addr := range d.Conf.CheckAlive {
		d.PingRecord[addr.String()] = 0
	}

	go func() {
		for {
			d.pingIPs()
			time.Sleep(time.Duration(d.Conf.CheckAliveInterval) * time.Second)
		}
	}()
}

// SpawnRoutine spawns a socks5 server.
func (config *Socks5Config) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	logger := vt.Logger
	logger.Verbosef("SOCKS5 SpawnRoutine started for bindAddress %s", config.BindAddress)
	var authMethods []socks5.Authenticator
	if username := config.Username; username != "" {
		logger.Verbosef("SOCKS5 using authentication with username %s", username)
		authMethods = append(authMethods, socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{username: config.Password},
		})
	} else {
		logger.Verbosef("SOCKS5 using no authentication")
		authMethods = append(authMethods, socks5.NoAuthAuthenticator{})
	}

	r := &TUNResolver{vt: vt}
	options := []socks5.Option{
		socks5.WithDial(func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ip := net.ParseIP(host)
			if ip == nil {
				// Domain name, resolve using TUNResolver
				_, resolvedIP, err := r.Resolve(ctx, host)
				if err != nil {
					return nil, err
				}
				addr = net.JoinHostPort(resolvedIP.String(), port)
			} else {
				// Already an IP — optionally prefer IPv4
				if ip.To4() == nil {
					// It's IPv6 — try to resolve an IPv4 if available
					_, ipv4Addr, err := r.Resolve(ctx, host)
					if err == nil && ipv4Addr.To4() != nil {
						addr = net.JoinHostPort(ipv4Addr.String(), port)
					}
				}
			}
			return vt.Tnet.DialContext(ctx, network, addr)
		}),
		socks5.WithResolver(r),
		socks5.WithAuthMethods(authMethods),
		socks5.WithBufferPool(bufferpool.NewPool(256 * 1024))}

	server := socks5.NewServer(options...)
	logger.Verbosef("SOCKS5 server object created")

	listener, err := net.Listen("tcp", config.BindAddress)
	if err != nil {
		logger.Errorf("SOCKS5 net.Listen failed: %v", err)
		return err
	}
	logger.Verbosef("SOCKS5 listener bound successfully on %s", config.BindAddress)

	go func() {
		<-ctx.Done()
		listener.Close()
		logger.Verbosef("SOCKS5 listener closed on context done")
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			var opErr *net.OpError
			if errors.As(err, &opErr) && errors.Is(opErr.Err, net.ErrClosed) {
				logger.Verbosef("SOCKS5 accept loop exited gracefully on listener close")
				return nil // Graceful shutdown
			}
			logger.Errorf("SOCKS5 accept error: %v", err)
			return err
		}
		go func(conn net.Conn) {
			defer func(conn net.Conn) {
				err := conn.Close()
				if err != nil && !errors.Is(err, net.ErrClosed) {
					logger.Errorf("SOCKS5 network connect close failed: %v", err)
				}
			}(conn)
			if err := server.ServeConn(conn); err != nil {
				if !strings.Contains(err.Error(), "connection reset by peer") &&
					err != io.EOF &&
					!strings.Contains(err.Error(), "operation aborted") && // read/write aborts
					!errors.Is(err, net.ErrClosed) && // Closed connections
					!errors.Is(err, context.Canceled) { // Context shutdown
					logger.Errorf("SOCKS5 ServeConn error for %s: %v", conn.RemoteAddr(), err)
				}
			}
		}(conn)
	}
}

// SpawnRoutine spawns an http server.
func (config *HTTPConfig) SpawnRoutine(ctx context.Context, vt *VirtualTun) error {
	logger := vt.Logger
	logger.Verbosef("HTTP SpawnRoutine started for bindAddress %s", config.BindAddress)

	server := &HTTPServer{
		config:       config,
		dial:         vt.Tnet.Dial,
		auth:         CredentialValidator{config.Username, config.Password},
		logger:       logger,
		authRequired: config.Username != "" || config.Password != "",
	}
	if server.authRequired {
		logger.Verbosef("HTTP using authentication with username %s", config.Username)
	} else {
		logger.Verbosef("HTTP using no authentication")
	}

	return server.ListenAndServe(ctx, "tcp", config.BindAddress)
}
