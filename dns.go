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

// dnsUDPBufSize is the EDNS0 requestor's buffer size advertised in queries
// and the size of the buffer replies are read into. Queries historically
// carried no OPT record, so upstreams capped replies at the 512-byte legacy
// limit (RFC 1035), and replies were read into a fixed 512-byte buffer that
// silently truncated anything larger. Replies for CNAME-heavy domains
// routinely exceed 512 bytes and failed to unmarshal on every lookup.
const dnsUDPBufSize = 4096

// Resolve resolves a hostname using DNS over the virtual tunnel interface.
// It prefers IPv4 (A records), but falls back to IPv6 (AAAA) if no A is found.
func (r *TUNResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if r.vt == nil || r.vt.Conf == nil {
		return ctx, nil, errors.New("no DNS servers configured")
	}
	if len(r.vt.Conf.DNS) == 0 {
		return r.resolveSystem(ctx, name)
	}

	dnsServer := r.vt.Conf.DNS[0].String()
	if !strings.Contains(dnsServer, ":") {
		dnsServer += ":53"
	}

	// Normalize: ensure trailing dot for absolute queries
	originalName := name
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	// List of names to try: original + appended search domains if unqualified
	var namesToQuery []string
	if strings.Count(strings.TrimSuffix(originalName, "."), ".") == 0 && len(r.vt.Conf.SearchDomains) > 0 {
		for _, domain := range r.vt.Conf.SearchDomains {
			full := strings.TrimSuffix(originalName, ".") + "." + strings.TrimPrefix(domain, ".") + "."
			namesToQuery = append(namesToQuery, full)
		}
	}
	namesToQuery = append(namesToQuery, name) // Fallback to original

	// Prefer A (IPv4)
	for _, qname := range namesToQuery {
		ip, err := r.queryDNS(ctx, dnsServer, qname, dns.TypeA)
		if err == nil && ip != nil {
			return ctx, ip, nil
		}
	}

	// Fallback to AAAA (IPv6)
	for _, qname := range namesToQuery {
		ip, err := r.queryDNS(ctx, dnsServer, qname, dns.TypeAAAA)
		if err == nil && ip != nil {
			return ctx, ip, nil
		}
	}

	return ctx, nil, errors.New("no A or AAAA records found after trying search domains")
}

// resolveSystem uses the OS resolver (underlay / "local" FakeDNS transport)
// when the tunnel config has no DNS servers. Prefer A, then AAAA.
func (r *TUNResolver) resolveSystem(ctx context.Context, name string) (context.Context, net.IP, error) {
	host := strings.TrimSuffix(name, ".")
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err == nil {
		for _, ip := range ips {
			if ip != nil {
				return ctx, ip, nil
			}
		}
	}
	ips, err = net.DefaultResolver.LookupIP(ctx, "ip6", host)
	if err == nil {
		for _, ip := range ips {
			if ip != nil {
				return ctx, ip, nil
			}
		}
	}
	return ctx, nil, errors.New("no A or AAAA records found via system DNS")
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
	// Advertise an EDNS0 buffer so upstreams may send replies larger than
	// the 512-byte legacy limit instead of truncating them (RFC 6891).
	msg.SetEdns0(dnsUDPBufSize, false)

	query, err := msg.Pack()
	if err != nil {
		return nil, err
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return nil, err
	}

	// Read the full reply: the advertised EDNS0 buffer allows replies up to
	// dnsUDPBufSize, and UDP reads discard anything beyond the buffer.
	buf := make([]byte, dnsUDPBufSize)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}

	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		return nil, err
	}

	if resp.Id != msg.Id {
		return nil, errors.New("mismatched DNS response ID")
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
