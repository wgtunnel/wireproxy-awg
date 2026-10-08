package wireproxy

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
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

func TestEDNSSizeForMTU(t *testing.T) {
	t.Parallel()
	cases := []struct {
		mtu  int
		want uint16
	}{
		{0, defaultEDNSSize},
		{-1, defaultEDNSSize},
		{1280, 1232},
		{1420, defaultEDNSSize},
		{576, 528},
		{520, dns.MinMsgSize},
	}
	for _, tc := range cases {
		if got := ednsSizeForMTU(tc.mtu); got != tc.want {
			t.Errorf("ednsSizeForMTU(%d)=%d want %d", tc.mtu, got, tc.want)
		}
	}
}

func TestQueryAdvertisesClampedEDNS(t *testing.T) {
	t.Parallel()
	seen := make(chan uint16, 1)
	addr, stop := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		if opt := r.IsEdns0(); opt != nil {
			seen <- opt.UDPSize()
		} else {
			seen <- 0
		}
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRecord("example.com.", "1.2.3.4")}
		_ = w.WriteMsg(m)
	})
	defer stop()

	r := &TUNResolver{
		vt:          &VirtualTun{Conf: &DeviceConfig{MTU: 1280, DNS: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}},
		dialContext: (&net.Dialer{}).DialContext,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := r.queryDNS(ctx, addr, "example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("queryDNS: %v", err)
	}
	if ip.String() != "1.2.3.4" {
		t.Fatalf("ip=%s", ip)
	}
	select {
	case sz := <-seen:
		if sz != 1232 {
			t.Fatalf("advertised UDPSize=%d want 1232", sz)
		}
	case <-ctx.Done():
		t.Fatal("server did not see a query")
	}
}

func TestQueryRetriesTCPOnTC(t *testing.T) {
	t.Parallel()
	addr, stop := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		if _, ok := w.RemoteAddr().(*net.UDPAddr); ok {
			m.Truncated = true
			_ = w.WriteMsg(m)
			return
		}
		m.Answer = []dns.RR{aRecord("example.com.", "9.9.9.9")}
		_ = w.WriteMsg(m)
	})
	defer stop()

	r := &TUNResolver{
		vt:          &VirtualTun{Conf: &DeviceConfig{MTU: 1420, DNS: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}},
		dialContext: (&net.Dialer{}).DialContext,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ip, err := r.queryDNS(ctx, addr, "example.com.", dns.TypeA)
	if err != nil {
		t.Fatalf("queryDNS: %v", err)
	}
	if ip.String() != "9.9.9.9" {
		t.Fatalf("ip=%s want 9.9.9.9", ip)
	}
}

func aRecord(name, ip string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP(ip).To4(),
	}
}

func startDNSServer(t *testing.T, h dns.HandlerFunc) (addr string, stop func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	udpAddr := pc.LocalAddr().(*net.UDPAddr)
	ln, err := net.Listen("tcp", udpAddr.String())
	if err != nil {
		pc.Close()
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	udpSrv := &dns.Server{PacketConn: pc, Handler: h, UDPSize: 4096, NotifyStartedFunc: func() { started <- struct{}{} }}
	tcpSrv := &dns.Server{Listener: ln, Handler: h, NotifyStartedFunc: func() { started <- struct{}{} }}
	go func() { _ = udpSrv.ActivateAndServe() }()
	go func() { _ = tcpSrv.ActivateAndServe() }()
	<-started
	<-started
	return udpAddr.String(), func() {
		_ = udpSrv.Shutdown()
		_ = tcpSrv.Shutdown()
	}
}
