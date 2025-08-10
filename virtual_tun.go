package wireproxy

import (
	"net"
	"sync"

	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	Tnet   *netstack.Net
	Dev    *device.Device
	Logger *device.Logger
	Uapi   net.Listener
	Conf   *DeviceConfig
	// PingRecord stores the last time an IP was pinged
	PingRecord     map[string]uint64
	PingRecordLock *sync.Mutex
}
