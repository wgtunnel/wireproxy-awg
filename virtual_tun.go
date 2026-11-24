package wireproxy

import (
	"context"
	"net"
	"net/netip"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	Tnet   *netstack.Net
	Dev    *device.Device
	Logger *device.Logger
	Uapi   net.Listener
	Conf   *DeviceConfig
	// DialDirectTCP4 handles an eligible numeric IPv4 destination. A false
	// handled result leaves the connection on the tunnel.
	DialDirectTCP4 func(context.Context, netip.Addr, string) (conn net.Conn, handled bool, err error)
	// PingRecord stores the last time an IP was pinged
	PingRecord     map[string]uint64
	PingRecordLock *sync.Mutex
}
