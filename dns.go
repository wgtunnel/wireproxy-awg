package wireproxy

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// TUNResolver forwards DNS resolution through the tunnel
type TUNResolver struct {
	vt *VirtualTun
}

// Resolve resolves a hostname using DNS over the virtual tunnel interface.
// It prefers IPv4 (A records), but falls back to IPv6 (AAAA) if no A is found.
func (r *TUNResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if r.vt == nil || len(r.vt.Conf.DNS) == 0 {
		return ctx, nil, errors.New("no DNS servers configured")
	}

	dnsServer := r.vt.Conf.DNS[0]
	if !strings.Contains(dnsServer, ":") {
		dnsServer += ":53"
	}

	// Ensure the domain name ends with a dot
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// Try A record first (IPv4)
	ip, err := r.queryDNS(ctx, dnsServer, name, dns.TypeA)
	if err == nil && ip != nil {
		return ctx, ip, nil
	}

	// If no IPv4 address found, try AAAA (IPv6)
	ip, err = r.queryDNS(ctx, dnsServer, name, dns.TypeAAAA)
	if err == nil && ip != nil {
		return ctx, ip, nil
	}

	return ctx, nil, errors.New("no A or AAAA records found")
}

// queryDNS sends a DNS query of the specified type and returns the first matching IP.
func (r *TUNResolver) queryDNS(ctx context.Context, dnsServer, name string, qtype uint16) (net.IP, error) {
	conn, err := r.vt.Tnet.DialContext(ctx, "udp", dnsServer)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = true
	msg.Id = uint16(rand.Intn(65536))

	query, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, err
	}

	for _, ans := range resp.Answer {
		switch rr := ans.(type) {
		case *dns.A:
			return rr.A, nil
		case *dns.AAAA:
			return rr.AAAA, nil
		}
	}

	return nil, errors.New("no matching DNS records found")
}
