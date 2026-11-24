package wireproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
)

// Untranslated FakeDNS destinations and loopback stay on the existing tunnel path.
var syntheticIPv4 = netip.MustParsePrefix("198.18.0.0/15")

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

// DialContext resolves the hostname before selecting a connection path.
func (d *tunDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	// A literal IP is dialed as given. Looking one up in DNS only ever returns
	// NXDOMAIN, and a client that sent an IPv6 literal chose IPv6.
	if net.ParseIP(host) == nil {
		// Domain name: resolve using the TUN resolver.
		_, resolvedIP, resolveErr := d.resolver.Resolve(ctx, host)
		if resolveErr != nil {
			return nil, resolveErr
		}
		host = resolvedIP.String()
		address = net.JoinHostPort(host, port)
	}

	if d.vt.DialDirectTCP4 != nil && (network == "tcp" || network == "tcp4") {
		if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() && !ip.IsLoopback() && !ip.IsUnspecified() && !syntheticIPv4.Contains(ip) {
			if conn, handled, err := d.vt.DialDirectTCP4(ctx, ip, port); handled || err != nil {
				return conn, err
			}
		}
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
