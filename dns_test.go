package wireproxy

import (
	"context"
	"errors"
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

// TestResolveBracketsIPv6DNSServer guards against a regression where an IPv6
// DNS server address was never given a port: the old code appended ":53"
// only when the address string had no colon, but every IPv6 address already
// has colons, so the port never got appended and the dial address was left
// as a bare, unparseable "::1".
func TestResolveBracketsIPv6DNSServer(t *testing.T) {
	t.Parallel()
	var dialed string
	r := &TUNResolver{
		vt: &VirtualTun{Conf: &DeviceConfig{DNS: []netip.Addr{netip.MustParseAddr("::1")}}},
		dialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			dialed = address
			return nil, errors.New("stub: no real dial needed for this assertion")
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _ = r.Resolve(ctx, "example.com")

	want := "[::1]:53"
	if dialed != want {
		t.Fatalf("dialed address=%q want %q", dialed, want)
	}
}

// TestResolveFallsBackToSecondDNSServer guards against only ever consulting
// DNS[0]: if the first configured server is unreachable, Resolve must still
// try the remaining configured servers instead of failing outright.
func TestResolveFallsBackToSecondDNSServer(t *testing.T) {
	t.Parallel()
	goodAddr, stop := startDNSServer(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{aRecord("example.com.", "9.8.7.6")}
		_ = w.WriteMsg(m)
	})
	defer stop()
	_, goodPort, err := net.SplitHostPort(goodAddr)
	if err != nil {
		t.Fatalf("split addr %s: %v", goodAddr, err)
	}

	r := &TUNResolver{
		vt: &VirtualTun{
			Conf: &DeviceConfig{
				DNS: []netip.Addr{
					netip.MustParseAddr("192.0.2.1"), // TEST-NET-1: always unreachable
					netip.MustParseAddr("127.0.0.1"),
				},
			},
		},
		// queryDNS always targets port 53; remap it to the ephemeral test
		// server port for the second (reachable) server, and fail fast for
		// the first so the test doesn't wait on a real network timeout.
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			if host == "192.0.2.1" {
				return nil, errors.New("stub: unreachable DNS server")
			}
			if port == "53" {
				address = net.JoinHostPort(host, goodPort)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, ip, err := r.Resolve(ctx, "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if ip.String() != "9.8.7.6" {
		t.Fatalf("ip=%s want 9.8.7.6 (did not fail over to second DNS server)", ip)
	}
}

// TestResolvePrefersAAAAOnV6OnlyTunnel guards against always asking for A
// first: on a tunnel with only an IPv6 interface address, an A answer would
// be undialable anyway, so Resolve should ask for AAAA first to avoid a
// wasted round trip on every lookup.
func TestResolvePrefersAAAAOnV6OnlyTunnel(t *testing.T) {
	t.Parallel()

	// The question type lives in the DNS message, so a real stub server
	// records the first one it sees rather than inspecting the dial address.
	// Buffered + non-blocking send: the resolver fires UDP and, since NXDOMAIN
	// never yields an answer, a TCP retry too, for both AAAA and A - the
	// handler must never block waiting for the channel or it stalls its own
	// response and the test hangs.
	seenCh := make(chan uint16, 8)
	addr, stop := startDNSServer(t, func(w dns.ResponseWriter, msg *dns.Msg) {
		if len(msg.Question) > 0 {
			select {
			case seenCh <- msg.Question[0].Qtype:
			default:
			}
		}
		m := new(dns.Msg)
		m.SetRcode(msg, dns.RcodeNameError) // NXDOMAIN: keep both A and AAAA tried
		_ = w.WriteMsg(m)
	})
	defer stop()
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split addr %s: %v", addr, err)
	}

	r := &TUNResolver{
		vt: &VirtualTun{
			Conf: &DeviceConfig{
				Address: []netip.Addr{netip.MustParseAddr("fd00::2")}, // v6-only
				DNS:     []netip.Addr{netip.MustParseAddr("127.0.0.1")},
			},
		},
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, p, splitErr := net.SplitHostPort(address)
			if splitErr != nil {
				return nil, splitErr
			}
			if p == "53" {
				address = net.JoinHostPort(host, port)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address)
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, _, _ = r.Resolve(ctx, "example.com")

	select {
	case seenFirst := <-seenCh:
		if seenFirst != dns.TypeAAAA {
			t.Fatalf("first query type=%d want AAAA(%d) on a v6-only tunnel", seenFirst, dns.TypeAAAA)
		}
	case <-ctx.Done():
		t.Fatal("server never saw a query")
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
