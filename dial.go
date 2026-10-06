package wireproxy

import (
	"context"
	"errors"
	"net"
)

// tunDialer dials through the tunnel netstack, resolving hostnames with the
// TUN resolver (search domains, IPv4 preference). SOCKS5, SOCKS4/4a and the
// HTTP proxy all share one dialer so resolution behavior is identical on
// every path and no dial site duplicates the resolution logic.
type tunDialer struct {
	vt       *VirtualTun
	resolver *TUNResolver
}

func newTUNDialer(vt *VirtualTun) *tunDialer {
	return &tunDialer{vt: vt, resolver: &TUNResolver{vt: vt}}
}

// DialContext resolves the hostname (if any) and dials through the tunnel.
func (d *tunDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	if ip := net.ParseIP(host); ip != nil {
		// Prefer IPv4 for literal IPv6 destinations when an A record exists.
		if ip.To4() == nil {
			if _, ipv4Addr, resolveErr := d.resolver.Resolve(ctx, host); resolveErr == nil && ipv4Addr.To4() != nil {
				address = net.JoinHostPort(ipv4Addr.String(), port)
			}
		}
	} else {
		// Domain name: resolve using the TUN resolver.
		_, resolvedIP, resolveErr := d.resolver.Resolve(ctx, host)
		if resolveErr != nil {
			return nil, resolveErr
		}
		address = net.JoinHostPort(resolvedIP.String(), port)
	}

	conn, err := d.vt.Tnet.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, errors.New("DialContext returned nil conn without error")
	}
	return conn, nil
}

// Dial is DialContext without a context, matching the net.Dialer signature
// the HTTP server uses.
func (d *tunDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}
