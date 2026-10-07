package wireproxy

import (
	"context"
	"testing"
	"time"
)

func TestTUNResolverSystemDNSWhenNoTunnelDNS(t *testing.T) {
	r := &TUNResolver{vt: &VirtualTun{Conf: &DeviceConfig{}}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, ip, err := r.Resolve(ctx, "localhost")
	if err != nil {
		t.Fatalf("system DNS fallback: %v", err)
	}
	if ip == nil {
		t.Fatal("expected an address for localhost")
	}
}
