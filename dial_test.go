package wireproxy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

func TestTUNDialerDirectTCP4(t *testing.T) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{netip.MustParseAddr("192.0.2.1")}, nil, 1420,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	directErr := errors.New("direct connection failed")
	for _, tc := range []struct {
		name, network, address string
		enabled, direct        bool
	}{
		{"default off", "tcp", "192.0.2.2:443", false, false},
		{"IPv4 TCP", "tcp", "192.0.2.2:443", true, true},
		{"explicit IPv4 TCP", "tcp4", "192.0.2.2:443", true, true},
		{"loopback", "tcp", "127.0.0.1:443", true, false},
		{"synthetic address", "tcp", "198.19.1.2:443", true, false},
		{"IPv4 UDP", "udp", "192.0.2.2:443", true, false},
		{"IPv6 TCP", "tcp", "[2001:db8::2]:443", true, false},
		{"mapped IPv6 literal", "tcp", "[::ffff:192.0.2.2]:443", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			vt := &VirtualTun{Tnet: tnet}
			if tc.enabled {
				vt.DialDirectTCP4 = func(_ context.Context, ip netip.Addr, port string) (net.Conn, bool, error) {
					if ip.String() != "192.0.2.2" || port != "443" {
						t.Fatalf("unexpected resolved address %s:%s", ip, port)
					}
					return nil, true, directErr
				}
			}
			conn, err := newTUNDialer(vt).DialContext(ctx, tc.network, tc.address)
			if conn != nil {
				_ = conn.Close()
			}
			if errors.Is(err, directErr) != tc.direct {
				t.Fatalf("unexpected path for %s %s: %v", tc.network, tc.address, err)
			}
		})
	}
}
